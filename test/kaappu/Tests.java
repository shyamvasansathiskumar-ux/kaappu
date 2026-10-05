package kaappu;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Zero-dependency test runner. Every published test vector from RFC 4226 Appendix D,
 * RFC 6238 Appendix B and RFC 4648 section 10 is checked, plus the vault and backup.
 * Run with: sh build.sh test
 */
public final class Tests {

    private static int passed = 0;
    private static final List<String> failures = new ArrayList<>();

    public static void main(String[] args) throws Exception {
        rfc4226Vectors();
        rfc6238Vectors();
        rfc4648Vectors();
        base32Leniency();
        otpauthUris();
        replayIsRefused();
        driftWindow();
        shamirRoundTrips();
        shamirBelowThresholdIsUseless();
        shareChecksumCatchesTypos();
        vaultRoundTrip();
        vaultRejectsWrongPasswordAndTampering();
        vaultRecoversWithSharesAfterPasswordChange();

        System.out.println(passed + " checks passed, " + failures.size() + " failed");
        failures.forEach(f -> System.out.println("  FAIL " + f));
        if (!failures.isEmpty()) System.exit(1);
    }

    // RFC 4226 Appendix D: secret "12345678901234567890", counters 0 to 9.
    static void rfc4226Vectors() {
        byte[] key = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        String[] expected = {"755224", "287082", "359152", "969429", "338314",
                             "254676", "287922", "162583", "399871", "520489"};
        for (int c = 0; c < expected.length; c++) {
            check("RFC 4226 counter " + c, expected[c], Hotp.generate(key, c, 6, Hotp.Algorithm.SHA1));
        }
    }

    // RFC 6238 Appendix B: 8 digits, 30 s step, one seed per hash function.
    static void rfc6238Vectors() {
        byte[] sha1 = "12345678901234567890".getBytes(StandardCharsets.US_ASCII);
        byte[] sha256 = "12345678901234567890123456789012".getBytes(StandardCharsets.US_ASCII);
        byte[] sha512 = "1234567890123456789012345678901234567890123456789012345678901234".getBytes(StandardCharsets.US_ASCII);
        long[] times = {59L, 1111111109L, 1111111111L, 1234567890L, 2000000000L, 20000000000L};
        String[][] expected = {
            {"94287082", "46119246", "90693936"},
            {"07081804", "68084774", "25091201"},
            {"14050471", "67062674", "99943326"},
            {"89005924", "91819424", "93441116"},
            {"69279037", "90698825", "38618901"},
            {"65353130", "77737706", "47863826"},
        };
        for (int i = 0; i < times.length; i++) {
            check("RFC 6238 SHA1 t=" + times[i], expected[i][0], Totp.at(new Account("t", "", sha1, 8, 30, Hotp.Algorithm.SHA1), times[i]));
            check("RFC 6238 SHA256 t=" + times[i], expected[i][1], Totp.at(new Account("t", "", sha256, 8, 30, Hotp.Algorithm.SHA256), times[i]));
            check("RFC 6238 SHA512 t=" + times[i], expected[i][2], Totp.at(new Account("t", "", sha512, 8, 30, Hotp.Algorithm.SHA512), times[i]));
        }
    }

    // RFC 4648 section 10.
    static void rfc4648Vectors() {
        String[][] v = {{"", ""}, {"f", "MY======"}, {"fo", "MZXQ===="}, {"foo", "MZXW6==="},
                        {"foob", "MZXW6YQ="}, {"fooba", "MZXW6YTB"}, {"foobar", "MZXW6YTBOI======"}};
        for (String[] p : v) {
            byte[] raw = p[0].getBytes(StandardCharsets.US_ASCII);
            check("base32 encode '" + p[0] + "'", p[1], Base32.encode(raw));
            check("base32 decode '" + p[1] + "'", p[0], new String(Base32.decode(p[1]), StandardCharsets.US_ASCII));
        }
    }

    static void base32Leniency() {
        check("lower case, spaces, no padding", "foobar",
              new String(Base32.decode("mzxw 6ytb oi"), StandardCharsets.US_ASCII));
        expectThrows("rejects '1' (not in the alphabet)", () -> Base32.decode("MZXW1YTB"));
    }

    static void otpauthUris() {
        Account a = Account.fromUri("otpauth://totp/ACME%20Co:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=ACME%20Co&algorithm=SHA1&digits=6&period=30");
        check("uri label", "alice@example.com", a.label());
        check("uri issuer", "ACME Co", a.issuer());
        Account b = Account.fromUri(a.toUri());
        check("uri round trip", Totp.at(a, 1_700_000_000L), Totp.at(b, 1_700_000_000L));
        expectThrows("issuer mismatch is refused",
                () -> Account.fromUri("otpauth://totp/Bank:alice?secret=JBSWY3DPEHPK3PXP&issuer=Evil"));
        expectThrows("80-bit floor", () -> Account.fromBase32("x", "JBSWY3DP"));
    }

    static void replayIsRefused() {
        Account a = Account.fromBase32("x", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        Totp.Verifier v = new Totp.Verifier(a, 1);
        long t = 1_700_000_000L;
        String code = Totp.at(a, t);
        check("first use accepted", Totp.Result.ACCEPTED, v.verify(code, t));
        check("same code again refused", Totp.Result.REPLAYED, v.verify(code, t + 5));
        check("wrong code rejected", Totp.Result.REJECTED, v.verify(code.equals("000000") ? "111111" : "000000", t));
    }

    static void driftWindow() {
        Account a = Account.fromBase32("x", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP");
        long t = 1_700_000_000L;
        check("one step late accepted", Totp.Result.ACCEPTED, new Totp.Verifier(a, 1).verify(Totp.at(a, t - 30), t));
        check("three steps late rejected", Totp.Result.REJECTED, new Totp.Verifier(a, 1).verify(Totp.at(a, t - 90), t));
    }

    static void shamirRoundTrips() {
        byte[] secret = new byte[32];
        new java.security.SecureRandom().nextBytes(secret);
        Shamir.Share[] s = Shamir.split(secret, 3, 5);
        int[][] subsets = {{0, 1, 2}, {0, 2, 4}, {1, 3, 4}, {4, 3, 0}, {2, 3, 4}};
        for (int[] sub : subsets) {
            List<Shamir.Share> pick = new ArrayList<>();
            for (int i : sub) pick.add(s[i]);
            check("3-of-5 with shares " + Arrays.toString(sub), true, Arrays.equals(secret, Shamir.combine(pick)));
        }
        Shamir.Share[] two = Shamir.split(secret, 2, 3);
        check("2-of-3 via text encoding", true, Arrays.equals(secret,
                Shamir.combine(List.of(Shamir.Share.decode(two[2].encode()), Shamir.Share.decode(two[0].encode())))));
        expectThrows("duplicate share refused", () -> Shamir.combine(List.of(two[0], two[0])));
    }

    static void shamirBelowThresholdIsUseless() {
        byte[] secret = "kaappu".getBytes(StandardCharsets.US_ASCII);
        Shamir.Share[] s = Shamir.split(secret, 3, 5);
        expectThrows("2 shares of a 3-of-5 refused", () -> Shamir.combine(List.of(s[0], s[1])));
    }

    static void shareChecksumCatchesTypos() {
        String text = Shamir.split(new byte[] {1, 2, 3, 4}, 2, 3)[0].encode();
        char[] c = text.toCharArray();
        int i = text.indexOf('-', "kaappu-share-2-1-".length() - 1) + 2;
        c[i] = c[i] == 'a' ? 'b' : 'a';
        expectThrows("one wrong character is caught", () -> Shamir.Share.decode(new String(c)));
    }

    static void vaultRoundTrip() throws Exception {
        Path dir = Files.createTempDirectory("kaappu-test");
        Path file = dir.resolve("v.kpu");
        char[] pw = "correct horse battery".toCharArray();
        try (Vault v = Vault.create(file, pw.clone(), 100_000)) {
            v.add(Account.fromBase32("github", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
            v.save();
        }
        try (Vault v = Vault.open(file, pw.clone())) {
            check("account survives save and reopen", "github", v.accounts().get(0).label());
        }
        String raw = new String(Files.readAllBytes(file), StandardCharsets.ISO_8859_1);
        check("secret is not stored in plain text", false, raw.contains("JBSWY3DP") || raw.contains("github"));
    }

    static void vaultRejectsWrongPasswordAndTampering() throws Exception {
        Path file = Files.createTempDirectory("kaappu-test").resolve("v.kpu");
        try (Vault v = Vault.create(file, "correct horse battery".toCharArray(), 100_000)) {
            v.add(Account.fromBase32("mail", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
            v.save();
        }
        expectThrowsIo("wrong password", () -> Vault.open(file, "wrong horse battery".toCharArray()));
        byte[] bytes = Files.readAllBytes(file);
        bytes[bytes.length - 1] ^= 0x01;
        Files.write(file, bytes);
        expectThrowsIo("one flipped bit in the ciphertext", () -> Vault.open(file, "correct horse battery".toCharArray()));
    }

    static void vaultRecoversWithSharesAfterPasswordChange() throws Exception {
        Path file = Files.createTempDirectory("kaappu-test").resolve("v.kpu");
        Shamir.Share[] shares;
        try (Vault v = Vault.create(file, "first passphrase here".toCharArray(), 100_000)) {
            v.add(Account.fromBase32("bank", "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"));
            v.save();
            shares = v.backupShares(2, 3);
            v.changePassword("second passphrase here".toCharArray());
        }
        expectThrowsIo("old password no longer works", () -> Vault.open(file, "first passphrase here".toCharArray()));
        try (Vault v = Vault.openWithShares(file, List.of(shares[1], shares[2]))) {
            check("shares from before the password change still open it", "bank", v.accounts().get(0).label());
        }
        Shamir.Share[] other = Shamir.split(new byte[32], 2, 3);
        expectThrowsIo("shares from another vault are refused", () -> Vault.openWithShares(file, List.of(other[0], other[1])));
    }

    // --- tiny assertion helpers ---

    private static void check(String name, Object expected, Object actual) {
        if (expected.equals(actual)) {
            passed++;
        } else {
            failures.add(name + ": expected " + expected + ", got " + actual);
        }
    }

    private interface Thrower { void run() throws Exception; }

    private static void expectThrows(String name, Thrower t) {
        try {
            t.run();
            failures.add(name + ": expected an exception, none thrown");
        } catch (IllegalArgumentException e) {
            passed++;
        } catch (Exception e) {
            failures.add(name + ": wrong exception " + e);
        }
    }

    private static void expectThrowsIo(String name, Thrower t) {
        try {
            t.run();
            failures.add(name + ": expected an IOException, none thrown");
        } catch (java.io.IOException e) {
            passed++;
        } catch (Exception e) {
            failures.add(name + ": wrong exception " + e);
        }
    }
}
