# kaappu

*Kaappu* (காப்பு) is Tamil for protection. It is a command-line TOTP authenticator in plain Java with one feature most authenticator apps don't have: **you can't lose it.**

**Try it live:** [shyamvasansathiskumar-ux.github.io/kaappu](https://shyamvasansathiskumar-ux.github.io/kaappu/), the same maths running in your browser, with every RFC test vector checked on the page. The site's source is in [`docs/`](docs/).

The usual way people lose access to their 2FA accounts isn't a hacker. It's a dropped phone, a factory reset, or an app that never synced. Kaappu splits the key to your vault into shares using Shamir's Secret Sharing. Make three, give one to a parent, keep one in a drawer and one in your password manager, and any two of them will rebuild the vault. One share on its own reveals nothing.

```
$ kaappu backup 2 3
Any 2 of these 3 shares can open this vault without the password.
Store each one in a different place. Fewer than 2 reveal nothing.

  kaappu-share-2-1-267c54b2ca34fbcfdc334c2a7c5961db493010acd8b2e5ccf442de56d940bd24-11fb
  kaappu-share-2-2-b564e288628883c299b01c29d4695aa0047ca6420094226ee9312e60131f02a5-5216
  kaappu-share-2-3-c46c799ef315ab3053382c284579ba893fb13d18487f96f9e2e97e72552a9eda-f974

$ kaappu code
GitHub (shyam)                   754 478   25s left
```

It started as a project my dad set me: build an authenticator from the RFCs, without a library doing the interesting part. Everything here is written from the specifications: HMAC truncation, Base32, the otpauth:// format, the vault encryption and the secret-sharing maths.

## What it does

- **Codes** for any service that uses TOTP: Google, GitHub, Microsoft, banks. SHA-1, SHA-256 and SHA-512; 6, 7 or 8 digits; any period.
- **Encrypted vault.** AES-256-GCM, with the key derived from your password by PBKDF2-HMAC-SHA256 at 600,000 iterations. The file is chmod 600 and is written atomically, so a crash never leaves a half-written vault.
- **Shamir backup** of the vault key. Shares are taken of the data key, not the password, so they keep working after you change your password.
- **Replay-safe verification.** `Totp.Verifier` refuses a code whose time step has already been used, as RFC 6238 section 5.2 asks. Most tutorial implementations skip this.
- **QR tampering check.** If an otpauth URI's `issuer=` parameter disagrees with the issuer in its label, Kaappu refuses it rather than guessing.
- **Secrets never touch argv.** Secrets and passwords are only read from a hidden prompt, so they don't end up in shell history or `ps` output.
- **No dependencies.** Only the JDK. The whole program is about 1,100 lines of Java you can read in an evening.

## Build and run

Needs JDK 17 or newer.

```sh
sh build.sh test     # 70 checks, including every RFC test vector
sh build.sh          # builds build/kaappu.jar
java -jar build/kaappu.jar init
java -jar build/kaappu.jar add          # paste the otpauth:// URI or Base32 secret when asked
java -jar build/kaappu.jar code
java -jar build/kaappu.jar backup 2 3
```

To get the otpauth:// URI from a QR code, most services also show a "can't scan it?" text key. Paste that.

## Tests

`sh build.sh test` runs, among other things:

| Source | What is checked |
| --- | --- |
| RFC 4226 Appendix D | All 10 HOTP values for counters 0 to 9 |
| RFC 6238 Appendix B | All 18 TOTP values: 6 timestamps × SHA-1, SHA-256, SHA-512, including t = 20000000000 (past 2038) |
| RFC 4648 section 10 | Every Base32 encode and decode example |
| Vault | Round trip; wrong password refused; one flipped bit in the file refused; secret not present in plain text |
| Shamir | Every 3-of-5 combination tried; 2 of 3-of-5 refused; shares still valid after a password change; shares from another vault refused; a one-character typo caught |
| Verifier | Replay refused; one step of clock drift accepted; three steps rejected |

## Layout

```
src/kaappu/
  Base32.java     RFC 4648
  Hotp.java       RFC 4226: HMAC + dynamic truncation
  Totp.java       RFC 6238: time steps, drift window, replay-safe verifier
  Account.java    one account; otpauth:// parsing and building
  Vault.java      encrypted file: PBKDF2 + AES-GCM, two-key design
  Shamir.java     secret sharing over GF(2^8)
  Main.java       command line
test/kaappu/Tests.java
SECURITY.md       threat model: what this protects against, and what it doesn't
```

## Read this before trusting it with real accounts

This is a learning project that takes security seriously, not an audited product. [SECURITY.md](SECURITY.md) lists exactly what it defends against and where it stops. For your bank, keep using your phone's authenticator as well, and treat Kaappu as the backup you can actually recover.

## Licence

MIT. See [LICENSE](LICENSE).
