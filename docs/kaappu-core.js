// Kaappu in the browser: the same maths as the Java CLI (RFC 4226, RFC 6238, RFC 4648,
// Shamir over GF(2^8) with the AES polynomial). WebCrypto does HMAC and SHA-256; nothing else
// is imported. Shares use the CLI's text format, so a share made here opens a vault there.
const Kaappu = (() => {
  const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

  function base32Encode(bytes) {
    let bits = 0, value = 0, out = "";
    for (const b of bytes) {
      value = (value << 8) | b; bits += 8;
      while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
    }
    if (bits > 0) out += B32[(value << (5 - bits)) & 31];
    while (out.length % 8) out += "=";
    return out;
  }

  function base32Decode(text) {
    const clean = text.toUpperCase().replace(/[\s-]/g, "").replace(/=+$/, "");
    let bits = 0, value = 0; const out = [];
    for (const ch of clean) {
      const i = B32.indexOf(ch);
      if (i < 0) throw new Error(`'${ch}' is not a Base32 character`);
      value = (value << 5) | i; bits += 5;
      if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
    }
    return new Uint8Array(out);
  }

  const ALG = { SHA1: "SHA-1", SHA256: "SHA-256", SHA512: "SHA-512" };

  async function hotp(key, counter, digits = 6, alg = "SHA1") {
    const msg = new Uint8Array(8);
    let c = BigInt(counter);
    for (let i = 7; i >= 0; i--) { msg[i] = Number(c & 0xffn); c >>= 8n; }
    const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: ALG[alg] }, false, ["sign"]);
    const h = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg));
    const off = h[h.length - 1] & 0x0f;
    // & 0x7f drops the sign bit: without it these four bytes read as a negative int in Java.
    const bin = ((h[off] & 0x7f) << 24) | (h[off + 1] << 16) | (h[off + 2] << 8) | h[off + 3];
    return String(bin % 10 ** digits).padStart(digits, "0");
  }

  async function totp(account, unixSeconds) {
    const step = Math.floor(unixSeconds / account.period);
    return hotp(account.key, step, account.digits, account.algorithm);
  }

  function parseUri(uri) {
    const u = new URL(uri.trim());
    if (u.protocol !== "otpauth:" || u.host !== "totp") throw new Error("not an otpauth://totp/ URI");
    const label = decodeURIComponent(u.pathname.replace(/^\//, ""));
    const [labelIssuer, name] = label.includes(":") ? label.split(/:(.*)/s) : [null, label];
    const p = u.searchParams;
    const issuer = p.get("issuer");
    if (labelIssuer && issuer && labelIssuer.trim() !== issuer.trim())
      throw new Error(`issuer mismatch: label says "${labelIssuer}", parameter says "${issuer}". Refusing, as the CLI does.`);
    const key = base32Decode(p.get("secret") || "");
    if (key.length < 10) throw new Error("secret is shorter than 80 bits (RFC 4226 minimum is 128, recommended 160)");
    return {
      name: name.trim(), issuer: (issuer || labelIssuer || "").trim(), key,
      digits: Number(p.get("digits") || 6), period: Number(p.get("period") || 30),
      algorithm: (p.get("algorithm") || "SHA1").toUpperCase(),
    };
  }

  // ---- Shamir over GF(256), generator 3, reduction 0x11B (same tables as Shamir.java) ----
  const EXP = new Array(512), LOG = new Array(256);
  (() => {
    const mulSlow = (a, b) => { let p = 0; while (b) { if (b & 1) p ^= a; a <<= 1; if (a & 0x100) a ^= 0x11b; b >>= 1; } return p; };
    let x = 1;
    for (let i = 0; i < 255; i++) { EXP[i] = x; LOG[x] = i; x = mulSlow(x, 3); }
    for (let i = 255; i < 512; i++) EXP[i] = EXP[i - 255];
  })();
  const mul = (a, b) => (a && b ? EXP[LOG[a] + LOG[b]] : 0);
  const div = (a, b) => { if (!b) throw new Error("division by zero"); return a ? EXP[LOG[a] + 255 - LOG[b]] : 0; };
  const hex = (b) => Array.from(b, (x) => x.toString(16).padStart(2, "0")).join("");
  const unhex = (s) => new Uint8Array(s.match(/../g).map((h) => parseInt(h, 16)));

  async function checksum(body) {
    const d = new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(body)));
    return hex(d.slice(0, 2));
  }

  async function split(secret, k, n) {
    if (!(k >= 2 && k <= n && n <= 255)) throw new Error("need 2 ≤ threshold ≤ shares ≤ 255");
    const ys = Array.from({ length: n }, () => new Uint8Array(secret.length));
    const coef = new Uint8Array(k);
    for (let i = 0; i < secret.length; i++) {
      coef[0] = secret[i];
      crypto.getRandomValues(coef.subarray(1));
      for (let s = 0; s < n; s++) {
        let r = 0;
        for (let c = k - 1; c >= 0; c--) r = mul(r, s + 1) ^ coef[c];
        ys[s][i] = r;
      }
    }
    coef.fill(0);
    const out = [];
    for (let s = 0; s < n; s++) {
      const body = `kaappu-share-${k}-${s + 1}-${hex(ys[s])}`;
      out.push(`${body}-${await checksum(body)}`);
    }
    return out;
  }

  async function decodeShare(text) {
    const t = text.trim(), last = t.lastIndexOf("-");
    if (!t.startsWith("kaappu-share-") || last < 0) throw new Error("not a kaappu share");
    const body = t.slice(0, last);
    if ((await checksum(body)) !== t.slice(last + 1).toLowerCase()) throw new Error("checksum mismatch: a character was mistyped");
    const [k, x, y] = body.slice("kaappu-share-".length).split("-");
    if (y === undefined) throw new Error("malformed share");
    return { k: Number(k), x: Number(x), y: unhex(y) };
  }

  async function combine(texts) {
    const shares = [];
    for (const t of texts.filter((s) => s.trim())) shares.push(await decodeShare(t));
    if (!shares.length) throw new Error("no shares given");
    const { k, y: { length } } = shares[0];
    if (shares.length < k) throw new Error(`need ${k} shares, got ${shares.length}`);
    for (let a = 0; a < shares.length; a++) {
      if (shares[a].k !== k || shares[a].y.length !== length) throw new Error("shares come from different splits");
      for (let b = a + 1; b < shares.length; b++) if (shares[a].x === shares[b].x) throw new Error(`the same share was given twice (x=${shares[a].x})`);
    }
    const used = shares.slice(0, k), secret = new Uint8Array(length);
    for (let i = 0; i < length; i++) {
      let v = 0;
      for (let j = 0; j < used.length; j++) {
        let num = 1, den = 1;
        for (let m = 0; m < used.length; m++) if (m !== j) { num = mul(num, used[m].x); den = mul(den, used[j].x ^ used[m].x); }
        v ^= mul(used[j].y[i], div(num, den));
      }
      secret[i] = v;
    }
    return secret;
  }

  // ---- the published test vectors, runnable by anyone viewing the page ----
  async function selfTest() {
    const results = [];
    const ascii = (s) => new TextEncoder().encode(s);
    const k1 = ascii("12345678901234567890");
    const rfc4226 = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"];
    for (let c = 0; c < 10; c++) results.push({ name: `RFC 4226 · counter ${c}`, want: rfc4226[c], got: await hotp(k1, c) });
    const seeds = { SHA1: k1, SHA256: ascii("12345678901234567890123456789012"), SHA512: ascii("1234567890123456789012345678901234567890123456789012345678901234") };
    const v = [[59, "94287082", "46119246", "90693936"], [1111111109, "07081804", "68084774", "25091201"], [1111111111, "14050471", "67062674", "99943326"],
      [1234567890, "89005924", "91819424", "93441116"], [2000000000, "69279037", "90698825", "38618901"], [20000000000, "65353130", "77737706", "47863826"]];
    for (const [t, a, b, c] of v) {
      for (const [alg, want] of [["SHA1", a], ["SHA256", b], ["SHA512", c]])
        results.push({ name: `RFC 6238 · ${alg} · t=${t}`, want, got: await totp({ key: seeds[alg], digits: 8, period: 30, algorithm: alg }, t) });
    }
    for (const [plain, enc] of [["f", "MY======"], ["fo", "MZXQ===="], ["foo", "MZXW6==="], ["foob", "MZXW6YQ="], ["fooba", "MZXW6YTB"], ["foobar", "MZXW6YTBOI======"]])
      results.push({ name: `RFC 4648 · "${plain}"`, want: enc, got: base32Encode(ascii(plain)) });
    const secret = crypto.getRandomValues(new Uint8Array(32));
    const sh = await split(secret, 3, 5);
    results.push({ name: "Shamir · 3-of-5, shares 2,4,5", want: hex(secret), got: hex(await combine([sh[1], sh[3], sh[4]])) });
    let refused = "accepted";
    try { await combine([sh[0], sh[1]]); } catch { refused = "refused"; }
    results.push({ name: "Shamir · 2 shares of a 3-of-5", want: "refused", got: refused });
    return results.map((r) => ({ ...r, ok: r.want === r.got }));
  }

  return { base32Encode, base32Decode, hotp, totp, parseUri, split, combine, decodeShare, selfTest, hex, unhex };
})();
if (typeof module !== "undefined") module.exports = Kaappu;
