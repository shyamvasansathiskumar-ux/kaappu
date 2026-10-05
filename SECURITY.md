# Security model

What Kaappu protects, what it doesn't, and why each design decision was made. If you find a problem, open an issue. For anything that could put real accounts at risk, email shyamvasansathiskumar@gmail.com first.

## What is being protected

A TOTP secret is a long-lived key. Anyone who holds it can produce valid codes forever, until the account owner resets 2FA. So the secret matters more than any single code, and the threats below are mostly about the secret.

## Threats and how they are handled

| # | Threat | What Kaappu does | What's left over |
| --- | --- | --- | --- |
| T1 | Someone copies the vault file (stolen laptop, cloud backup, shared drive) | AES-256-GCM encryption. The key comes from PBKDF2-HMAC-SHA256 at 600,000 iterations with a random 16-byte salt, which makes each password guess costly | A weak password can still be guessed offline. Kaappu insists on 12+ characters; a 4 to 5 word passphrase is much stronger |
| T2 | Someone edits the vault file (to downgrade the iteration count, splice in another file's header, or flip bits) | The whole header is authenticated as GCM associated data. Any change fails decryption with an error rather than producing garbage | None known |
| T3 | You lose your phone, laptop or password | Shamir k-of-n shares of the data key. Any k rebuild the vault; fewer than k carry no information about it | Whoever holds k shares and the vault file can open it. Choose holders you trust, and don't keep two shares in the same place |
| T4 | A code is shoulder-surfed or phished, then replayed | `Totp.Verifier` records the last accepted time step and refuses that step or anything earlier (RFC 6238 section 5.2) | Only applies when Kaappu does the verifying. Codes you type into websites are only protected by those sites' own replay checks |
| T5 | Timing attacks on verification | The comparison uses `MessageDigest.isEqual`, and every step in the drift window is checked even after a match, so response time doesn't reveal which step matched | Shamir's GF(256) arithmetic uses lookup tables. That only matters if an attacker can time recovery on your machine, at which point they have bigger options |
| T6 | Secrets leak through shell history or the process list | Secrets and passwords are only read from a hidden prompt (`Console.readPassword`), never from command-line arguments | When input is piped (scripts, tests) it is not hidden. Don't pipe real secrets on shared machines |
| T7 | Secrets left in memory | Passwords are `char[]` and keys are `byte[]`, overwritten after use; `PBEKeySpec.clearPassword()` is called; the vault wipes keys and secrets on `close()` | The JVM can copy objects during garbage collection, and `String`s can't be wiped, so an attacker who can read process memory (a heap dump, a debugger, malware) may still find secrets. Wiping narrows the window but cannot close it in Java |
| T8 | A tampered or phishing QR code | If an otpauth URI's `issuer=` disagrees with the issuer in its label, the account is refused | A fully consistent malicious QR code, with matching issuer fields, can't be detected by any authenticator |
| T9 | Weak secrets issued by a service | Secrets under 80 bits are refused. Under 128 bits (RFC 4226's minimum) you get a warning | The service chose the secret, so Kaappu can only warn |
| T10 | A crash during save | Writes go to a temporary file that is then moved into place, atomically where the file system supports it | None known |

## Out of scope

- **Malware on your computer.** If something can read your keystrokes or your process memory, no authenticator on that machine is safe. This is why hardware keys (FIDO2) exist.
- **Real-time phishing proxies.** A fake login page that forwards your code to the real site within 30 seconds defeats TOTP completely. That's a limit of TOTP, not of this implementation. Use passkeys or FIDO2 where a service offers them.
- **Clock attacks.** Codes depend on your system clock. Someone who can set your clock forward can harvest future codes. Keep NTP on.

## Design decisions

**Two keys, not one.** A random data key encrypts the accounts, and the password-derived key only wraps the data key. This is what lets Shamir shares survive a password change, and it means changing your password only re-encrypts 32 bytes.

**PBKDF2 rather than Argon2.** Argon2id is the better function, but it isn't in the JDK, and this project has no dependencies by design. PBKDF2-HMAC-SHA256 at 600,000 iterations is the OWASP Password Storage Cheat Sheet's figure for PBKDF2. If Kaappu ever takes a dependency, Argon2id comes first.

**No HOTP accounts.** Counter-based codes need the counter stored and kept in step with the server. Getting that wrong locks you out, and almost no service uses HOTP any more.

**Shares carry a checksum.** Two bytes of SHA-256 over each share's text catch copying mistakes before recovery is attempted. The checksum covers the share, not the secret, so it reveals nothing.

## References

- RFC 4226, HOTP: https://www.rfc-editor.org/rfc/rfc4226
- RFC 6238, TOTP: https://www.rfc-editor.org/rfc/rfc6238
- RFC 4648, Base32: https://www.rfc-editor.org/rfc/rfc4648
- Google Authenticator Key URI format: https://github.com/google/google-authenticator/wiki/Key-Uri-Format
- NIST SP 800-38D, GCM: https://csrc.nist.gov/pubs/sp/800/38/d/final
- OWASP Password Storage Cheat Sheet: https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html
- Adi Shamir, "How to Share a Secret", Communications of the ACM, 1979
