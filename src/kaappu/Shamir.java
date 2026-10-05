package kaappu;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.HexFormat;
import java.util.List;

/**
 * Shamir's Secret Sharing over GF(2^8), used to back up the vault key.
 *
 * Splitting a secret into n shares with threshold k means any k shares rebuild it
 * and any k - 1 shares reveal nothing about it. With 2-of-3, one share can sit with
 * a parent, one in a drawer and one in a password manager: losing a phone, or one
 * share leaking, costs nothing.
 *
 * Each byte of the secret is the constant term of its own random polynomial of
 * degree k - 1. A share is that polynomial evaluated at x = 1..n for every byte.
 * Arithmetic is in GF(256) with the AES reduction polynomial x^8 + x^4 + x^3 + x + 1.
 */
public final class Shamir {

    private static final SecureRandom RANDOM = new SecureRandom();
    private static final int[] EXP = new int[512];
    private static final int[] LOG = new int[256];

    static {
        // Log and antilog tables with generator 3, which generates the whole field.
        int x = 1;
        for (int i = 0; i < 255; i++) {
            EXP[i] = x;
            LOG[x] = i;
            x = mulSlow(x, 3);
        }
        for (int i = 255; i < 512; i++) {
            EXP[i] = EXP[i - 255];
        }
    }

    private Shamir() {}

    public record Share(int threshold, int x, byte[] y) {
        private static final String PREFIX = "kaappu-share";

        /** Text form: kaappu-share-<k>-<x>-<hex bytes>-<4-hex checksum>. The checksum catches typos only. */
        public String encode() {
            String body = PREFIX + "-" + threshold + "-" + x + "-" + HexFormat.of().formatHex(y);
            return body + "-" + checksum(body);
        }

        public static Share decode(String text) {
            String t = text.trim();
            int lastDash = t.lastIndexOf('-');
            if (!t.startsWith(PREFIX + "-") || lastDash < 0) {
                throw new IllegalArgumentException("not a kaappu share");
            }
            String body = t.substring(0, lastDash);
            if (!checksum(body).equalsIgnoreCase(t.substring(lastDash + 1))) {
                throw new IllegalArgumentException("share checksum mismatch: check it was copied exactly");
            }
            String[] parts = body.substring(PREFIX.length() + 1).split("-");
            if (parts.length != 3) {
                throw new IllegalArgumentException("malformed share");
            }
            return new Share(Integer.parseInt(parts[0]), Integer.parseInt(parts[1]), HexFormat.of().parseHex(parts[2]));
        }

        private static String checksum(String body) {
            try {
                byte[] d = MessageDigest.getInstance("SHA-256").digest(body.getBytes(java.nio.charset.StandardCharsets.US_ASCII));
                return HexFormat.of().formatHex(d, 0, 2);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    }

    public static Share[] split(byte[] secret, int threshold, int shares) {
        if (threshold < 2 || threshold > shares || shares > 255) {
            throw new IllegalArgumentException("need 2 <= threshold <= shares <= 255");
        }
        byte[][] ys = new byte[shares][secret.length];
        int[] coefficients = new int[threshold];
        for (int i = 0; i < secret.length; i++) {
            coefficients[0] = secret[i] & 0xFF;
            for (int c = 1; c < threshold; c++) {
                coefficients[c] = RANDOM.nextInt(256);
            }
            for (int s = 0; s < shares; s++) {
                ys[s][i] = (byte) evaluate(coefficients, s + 1);
            }
        }
        java.util.Arrays.fill(coefficients, 0);
        Share[] out = new Share[shares];
        for (int s = 0; s < shares; s++) {
            out[s] = new Share(threshold, s + 1, ys[s]);
        }
        return out;
    }

    public static byte[] combine(List<Share> shares) {
        if (shares.isEmpty()) {
            throw new IllegalArgumentException("no shares given");
        }
        int threshold = shares.get(0).threshold();
        int length = shares.get(0).y().length;
        if (shares.size() < threshold) {
            throw new IllegalArgumentException("need " + threshold + " shares, got " + shares.size());
        }
        for (int a = 0; a < shares.size(); a++) {
            Share s = shares.get(a);
            if (s.threshold() != threshold || s.y().length != length) {
                throw new IllegalArgumentException("shares come from different splits");
            }
            for (int b = a + 1; b < shares.size(); b++) {
                if (shares.get(b).x() == s.x()) {
                    throw new IllegalArgumentException("the same share was given twice (x=" + s.x() + ")");
                }
            }
        }
        List<Share> used = shares.subList(0, threshold);
        byte[] secret = new byte[length];
        for (int i = 0; i < length; i++) {
            // Lagrange interpolation at x = 0. In GF(2^8), subtraction is XOR.
            int value = 0;
            for (int j = 0; j < used.size(); j++) {
                int xj = used.get(j).x();
                int numerator = 1;
                int denominator = 1;
                for (int m = 0; m < used.size(); m++) {
                    if (m == j) continue;
                    int xm = used.get(m).x();
                    numerator = mul(numerator, xm);
                    denominator = mul(denominator, xj ^ xm);
                }
                int basis = div(numerator, denominator);
                value ^= mul(used.get(j).y()[i] & 0xFF, basis);
            }
            secret[i] = (byte) value;
        }
        return secret;
    }

    private static int evaluate(int[] coefficients, int x) {
        int result = 0;
        for (int c = coefficients.length - 1; c >= 0; c--) {
            result = mul(result, x) ^ coefficients[c];
        }
        return result;
    }

    static int mul(int a, int b) {
        if (a == 0 || b == 0) return 0;
        return EXP[LOG[a] + LOG[b]];
    }

    static int div(int a, int b) {
        if (b == 0) throw new ArithmeticException("division by zero in GF(256)");
        if (a == 0) return 0;
        return EXP[LOG[a] + 255 - LOG[b]];
    }

    /** Carry-less "Russian peasant" multiply, only used to build the tables. */
    private static int mulSlow(int a, int b) {
        int p = 0;
        while (b != 0) {
            if ((b & 1) != 0) p ^= a;
            a <<= 1;
            if ((a & 0x100) != 0) a ^= 0x11B;
            b >>= 1;
        }
        return p;
    }
}
