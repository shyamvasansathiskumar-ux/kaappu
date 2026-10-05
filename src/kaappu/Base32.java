package kaappu;

import java.io.ByteArrayOutputStream;

/**
 * RFC 4648 Base32, the encoding every authenticator app uses for shared secrets.
 *
 * Decoding is forgiving in the ways real-world QR codes and manual entry need:
 * lower case, spaces, hyphens and missing "=" padding are all accepted.
 * Anything outside the alphabet is rejected rather than silently skipped,
 * because a mistyped secret should fail loudly, not produce wrong codes.
 */
public final class Base32 {

    private static final char[] ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567".toCharArray();
    private static final int[] LOOKUP = new int[128];

    static {
        java.util.Arrays.fill(LOOKUP, -1);
        for (int i = 0; i < ALPHABET.length; i++) {
            LOOKUP[ALPHABET[i]] = i;
            LOOKUP[Character.toLowerCase(ALPHABET[i])] = i;
        }
    }

    private Base32() {}

    public static String encode(byte[] data) {
        StringBuilder out = new StringBuilder((data.length + 4) / 5 * 8);
        int buffer = 0;
        int bits = 0;
        for (byte b : data) {
            buffer = (buffer << 8) | (b & 0xFF);
            bits += 8;
            while (bits >= 5) {
                out.append(ALPHABET[(buffer >> (bits - 5)) & 0x1F]);
                bits -= 5;
            }
        }
        if (bits > 0) {
            out.append(ALPHABET[(buffer << (5 - bits)) & 0x1F]);
        }
        while (out.length() % 8 != 0) {
            out.append('=');
        }
        return out.toString();
    }

    public static byte[] decode(String text) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        boolean paddingSeen = false;
        for (int i = 0; i < text.length(); i++) {
            char c = text.charAt(i);
            if (c == ' ' || c == '-' || c == '\t') {
                continue;
            }
            if (c == '=') {
                paddingSeen = true;
                continue;
            }
            if (paddingSeen) {
                throw new IllegalArgumentException("Base32: data after '=' padding at position " + i);
            }
            int value = c < 128 ? LOOKUP[c] : -1;
            if (value < 0) {
                throw new IllegalArgumentException("Base32: invalid character '" + c + "' at position " + i);
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                out.write((buffer >> (bits - 8)) & 0xFF);
                bits -= 8;
            }
        }
        return out.toByteArray();
    }
}
