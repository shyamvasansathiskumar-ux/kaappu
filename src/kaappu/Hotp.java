package kaappu;

import java.security.GeneralSecurityException;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HOTP, RFC 4226: an HMAC over an 8-byte counter, cut down to a short decimal code.
 */
public final class Hotp {

    private static final int[] POWERS_OF_TEN = {
        1, 10, 100, 1_000, 10_000, 100_000, 1_000_000, 10_000_000, 100_000_000
    };

    private Hotp() {}

    public static String generate(byte[] key, long counter, int digits, Algorithm algorithm) {
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("digits must be 6, 7 or 8 (RFC 4226 section 5.3)");
        }
        byte[] hash = hmac(algorithm, key, counterBytes(counter));

        // Dynamic truncation (RFC 4226 section 5.3): the low nibble of the last byte
        // picks where the 4-byte window starts; the top bit is masked off so the
        // result is the same whether a platform treats it as signed or unsigned.
        int offset = hash[hash.length - 1] & 0x0F;
        int binary = ((hash[offset] & 0x7F) << 24)
                | ((hash[offset + 1] & 0xFF) << 16)
                | ((hash[offset + 2] & 0xFF) << 8)
                | (hash[offset + 3] & 0xFF);

        int code = binary % POWERS_OF_TEN[digits];
        return String.format("%0" + digits + "d", code);
    }

    /** The counter as 8 big-endian bytes, as RFC 4226 section 5.2 requires. */
    static byte[] counterBytes(long counter) {
        byte[] out = new byte[8];
        for (int i = 7; i >= 0; i--) {
            out[i] = (byte) (counter & 0xFF);
            counter >>>= 8;
        }
        return out;
    }

    private static byte[] hmac(Algorithm algorithm, byte[] key, byte[] message) {
        try {
            Mac mac = Mac.getInstance(algorithm.jceName);
            mac.init(new SecretKeySpec(key, algorithm.jceName));
            return mac.doFinal(message);
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException("HMAC unavailable: " + algorithm.jceName, e);
        }
    }

    public enum Algorithm {
        SHA1("HmacSHA1"),
        SHA256("HmacSHA256"),
        SHA512("HmacSHA512");

        final String jceName;

        Algorithm(String jceName) {
            this.jceName = jceName;
        }

        public static Algorithm parse(String name) {
            return switch (name.toUpperCase().replace("-", "")) {
                case "SHA1" -> SHA1;
                case "SHA256" -> SHA256;
                case "SHA512" -> SHA512;
                default -> throw new IllegalArgumentException("Unsupported algorithm: " + name);
            };
        }
    }
}
