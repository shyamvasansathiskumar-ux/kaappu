/* Kaappu page logic: live codes, the four-step walkthrough, verify-once, split/rebuild, test vectors. */
(() => {
  const $ = (id) => document.getElementById(id);
  const DEMO = { name: "shyam", issuer: "Demo", key: Kaappu.base32Decode("JBSWY3DPEHPK3PXP"), digits: 6, period: 30, algorithm: "SHA1" };
  const fmt = (c) => (c.length === 6 ? c.slice(0, 3) + " " + c.slice(3) : c.length === 8 ? c.slice(0, 4) + " " + c.slice(4) : c);
  const hex2 = (b) => b.toString(16).padStart(2, "0");

  /* ---------- hero chip + four-step walkthrough (demo secret, live) ---------- */
  let hmacKey = null;
  async function hmacBytes(counter) {
    if (!hmacKey) hmacKey = await crypto.subtle.importKey("raw", DEMO.key, { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const msg = new Uint8Array(8); let c = BigInt(counter);
    for (let i = 7; i >= 0; i--) { msg[i] = Number(c & 0xffn); c >>= 8n; }
    return new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, msg));
  }
  const byteEls = [];
  for (let i = 0; i < 20; i++) { const s = document.createElement("span"); s.textContent = "··"; $("sBytes").append(s); byteEls.push(s); }
  let lastStep = -1;
  async function walk() {
    const now = Date.now() / 1000, unix = Math.floor(now), step = Math.floor(unix / 30), left = 30 - (unix % 30);
    $("sUnix").textContent = unix.toLocaleString("en-US");
    $("sStep").textContent = step.toLocaleString("en-US");
    $("sBar").style.width = `${((30 - left + 1) / 30) * 100}%`;
    $("heroSecs").textContent = left + "s";
    $("heroArc").style.strokeDashoffset = String(106.8 * (1 - left / 30));
    if (step === lastStep) return;
    lastStep = step;
    const h = await hmacBytes(step), off = h[19] & 0x0f;
    byteEls.forEach((s, i) => { s.textContent = hex2(h[i]); s.className = (i >= off && i < off + 4 ? "cut" : "") + (i === 19 ? " off" : ""); });
    $("sOff").textContent = `0x${off.toString(16)} = ${off}`;
    const four = [...h.slice(off, off + 4)];
    $("sFour").textContent = four.map(hex2).join(" ");
    const bin = ((four[0] & 0x7f) << 24) | (four[1] << 16) | (four[2] << 8) | four[3];
    $("sInt").textContent = bin.toLocaleString("en-US");
    const code = String(bin % 1e6).padStart(6, "0");
    const check = await Kaappu.totp(DEMO, now);
    $("sCode").textContent = fmt(code);
    $("heroCode").textContent = fmt(code === check ? code : check);
    window.Site && (Site.kaappuStep = step);
  }

  /* ---------- tool: codes + verify once ---------- */
  let account = null;
  const used = new Set();
  function load() {
    const v = $("src").value.trim();
    try {
      account = v.startsWith("otpauth://") ? Kaappu.parseUri(v)
        : { name: "secret", issuer: "", key: Kaappu.base32Decode(v), digits: 6, period: 30, algorithm: "SHA1" };
      if (account.key.length < 10) throw new Error("secret is shorter than 80 bits");
      $("genmsg").className = "msg ok";
      $("genmsg").textContent = `${account.issuer ? account.issuer + " · " : ""}${account.name} · ${account.algorithm} · ${account.digits} digits · ${account.period}s`;
      used.clear(); tick();
    } catch (e) {
      account = null; $("genmsg").className = "msg bad"; $("genmsg").textContent = "Refused: " + e.message;
      $("now").textContent = "––– –––"; $("next").textContent = ""; $("secs").textContent = "–";
    }
  }
  async function tick() {
    if (!account) return;
    const t = Date.now() / 1000, p = account.period, left = p - (Math.floor(t) % p);
    $("now").textContent = fmt(await Kaappu.totp(account, t));
    $("next").textContent = "next  " + fmt(await Kaappu.totp(account, t + p));
    $("secs").textContent = left;
    $("arc").style.strokeDashoffset = String(169.6 * (1 - left / p));
  }
  async function verify() {
    const m = $("vmsg");
    if (!account) { m.className = "msg bad"; m.textContent = "Load a valid secret first."; return; }
    const code = $("tryCode").value.replace(/\s/g, ""), t = Math.floor(Date.now() / 1000), step = Math.floor(t / account.period);
    if (!/^\d{6,8}$/.test(code)) { m.className = "msg bad"; m.textContent = `Type the ${account.digits}-digit code.`; return; }
    for (const d of [0, -1, 1]) {
      if ((await Kaappu.totp(account, (step + d) * account.period)) === code) {
        if (used.has(step + d)) { m.className = "msg bad"; m.textContent = `REPLAYED · step ${step + d} was already used. Refused.`; return; }
        used.add(step + d);
        m.className = "msg ok"; m.textContent = `ACCEPTED · step ${step + d}${d ? ` (${d > 0 ? "+" : ""}${d} step of clock drift)` : ""}. Press Verify again.`; return;
      }
    }
    m.className = "msg bad"; m.textContent = "REJECTED · no match within one step either side.";
  }
  $("src").addEventListener("input", load);
  $("verify").addEventListener("click", verify);
  $("tryCode").addEventListener("keydown", (e) => e.key === "Enter" && verify());
  document.querySelectorAll(".chip[data-uri]").forEach((b) => b.addEventListener("click", () => { $("src").value = b.dataset.uri; load(); }));

  /* ---------- split / rebuild ---------- */
  let lastShares = [];
  function syncK() {
    const n = +$("n").value;
    [...$("k").options].forEach((o) => (o.disabled = +o.value > n));
    if (+$("k").value > n) $("k").value = String(n);
  }
  async function doSplit() {
    syncK();
    const k = +$("k").value, n = +$("n").value, secret = $("secret").value;
    if (!secret) { $("cmsg").className = "msg bad"; $("cmsg").textContent = "Type a secret to split."; return; }
    lastShares = await Kaappu.split(new TextEncoder().encode(secret), k, n);
    $("sharelist").innerHTML = "";
    lastShares.forEach((s, i) => {
      const li = document.createElement("li"), x = document.createElement("span"), c = document.createElement("code"), b = document.createElement("button");
      x.className = "x"; x.textContent = String(i + 1).padStart(2, "0");
      c.textContent = s; c.title = s; b.textContent = "Copy";
      b.addEventListener("click", () => navigator.clipboard?.writeText(s).then(() => { b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1400); }));
      li.append(x, c, b); $("sharelist").append(li);
    });
    // Rebuild from the last k shares, to show it isn't "the first ones".
    $("pasted").value = lastShares.slice(-k).join("\n");
    await doCombine();
  }
  async function doCombine() {
    const m = $("cmsg");
    try {
      const lines = $("pasted").value.split("\n").filter((s) => s.trim());
      const bytes = await Kaappu.combine(lines);
      const xs = (await Promise.all(lines.map((l) => Kaappu.decodeShare(l)))).map((s) => s.x);
      m.className = "msg ok"; m.textContent = `Rebuilt from shares ${xs.join(", ")}: "${new TextDecoder().decode(bytes)}"`;
      window.Site && (Site.kaappuShares = xs);
    } catch (e) { m.className = "msg bad"; m.textContent = "Refused: " + e.message; }
  }
  $("n").addEventListener("change", syncK);
  $("dosplit").addEventListener("click", doSplit);
  $("docombine").addEventListener("click", doCombine);
  $("useone").addEventListener("click", () => { $("pasted").value = lastShares.slice(0, 1).join("\n"); doCombine(); });
  $("typo").addEventListener("click", () => {
    const k = +$("k").value, s = lastShares.slice(0, k);
    if (!s.length) return;
    const t = s[0], i = 20 + Math.floor(Math.random() * 20), ch = t[i] === "a" ? "b" : "a";
    s[0] = t.slice(0, i) + ch + t.slice(i + 1);
    $("pasted").value = s.join("\n"); doCombine();
  });

  /* ---------- test vectors ---------- */
  const short = (v) => (v.length > 18 ? v.slice(0, 16) + "…" : v);
  async function vectors() {
    const r = await Kaappu.selfTest(), ok = r.filter((x) => x.ok).length;
    $("passed").textContent = `${ok}/${r.length}`;
    $("tallytext").textContent = ok === r.length ? "checks passed in this browser" : "checks passed. Something is wrong in this browser.";
    $("rows").innerHTML = r.map((x) => `<tr><td>${x.name}</td><td title="${x.want}">${short(x.want)}</td><td title="${x.got}">${short(x.got)}</td><td class="${x.ok ? "p" : "f"}">${x.ok ? "✓" : "FAIL"}</td></tr>`).join("");
    window.__selfTest = { ok, total: r.length };
  }

  /* ---------- pinned horizontal walkthrough ---------- */
  function pin() {
    const sec = $("how"), cards = $("cards");
    if (!window.gsap || !window.ScrollTrigger || Site.reduce || innerWidth < 900) { sec.classList.add("no-pin"); return; }
    const dist = () => Math.max(0, cards.scrollWidth - innerWidth);
    gsap.to(cards, { x: () => -dist(), ease: "none",
      scrollTrigger: { trigger: "#hscroll", start: "top 12%", end: () => "+=" + dist(), pin: true, scrub: 0.8, invalidateOnRefresh: true, anticipatePin: 1 } });
    gsap.utils.toArray(".step").forEach((s, i) => gsap.from(s, { rotate: 3, y: 60, opacity: 0, duration: 1, ease: "expo.out", delay: i * 0.06,
      scrollTrigger: { trigger: "#hscroll", start: "top 75%", once: true } }));
  }

  load(); walk(); tick(); doSplit(); vectors(); pin();
  setInterval(() => { walk(); tick(); }, 1000);
})();
