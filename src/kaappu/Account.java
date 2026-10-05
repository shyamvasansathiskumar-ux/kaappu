package kaappu;

import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

/**
 * One saved 2FA account. Built from an otpauth:// URI (the text inside a 2FA QR code)
 * or from a bare Base32 secret.
 */
public record Account(String label, String issuer, byte[] secret, int digits, int period, Hotp.Algorithm algorithm) {

    public Account {
        if (label == null || label.isBlank()) {
            throw new IllegalArgumentException("label is required");
        }
        if (label.contains("\t") || label.contains("\n") || (issuer != null && (issuer.contains("\t") || issuer.contains("\n")))) {
            throw new IllegalArgumentException("label and issuer cannot contain tabs or newlines");
        }
        if (secret == null || secret.length < 10) {
            // RFC 4226 section 4 asks for at least 128 bits and recommends 160. Many real
            // services still issue 80-bit secrets, so 80 is the floor and anything weaker
            // is refused; isWeak() lets the CLI warn about the 80-127 bit range.
            throw new IllegalArgumentException("secret is shorter than 80 bits; refusing a weak key");
        }
        if (digits < 6 || digits > 8) {
            throw new IllegalArgumentException("digits must be 6, 7 or 8");
        }
        if (period < 15 || period > 300) {
            throw new IllegalArgumentException("period must be between 15 and 300 seconds");
        }
        secret = secret.clone();
        issuer = issuer == null ? "" : issuer;
    }

    @Override
    public byte[] secret() {
        return secret.clone();
    }

    /** True when the secret is below the 128-bit minimum of RFC 4226 section 4. */
    public boolean isWeak() {
        return secret.length < 16;
    }

    public static Account fromBase32(String label, String base32Secret) {
        return new Account(label, "", Base32.decode(base32Secret), 6, Totp.DEFAULT_PERIOD, Hotp.Algorithm.SHA1);
    }

    /** Parses otpauth://totp/Issuer:account?secret=...&issuer=...&digits=...&period=...&algorithm=... */
    public static Account fromUri(String uri) {
        String prefix = "otpauth://totp/";
        if (!uri.startsWith(prefix)) {
            if (uri.startsWith("otpauth://hotp/")) {
                throw new IllegalArgumentException("HOTP (counter-based) accounts are not supported; only TOTP");
            }
            throw new IllegalArgumentException("not an otpauth://totp/ URI");
        }
        String rest = uri.substring(prefix.length());
        int q = rest.indexOf('?');
        if (q < 0) {
            throw new IllegalArgumentException("otpauth URI has no parameters");
        }
        String label = decode(rest.substring(0, q));
        Map<String, String> params = new HashMap<>();
        for (String pair : rest.substring(q + 1).split("&")) {
            int eq = pair.indexOf('=');
            if (eq > 0) {
                params.put(pair.substring(0, eq).toLowerCase(), decode(pair.substring(eq + 1)));
            }
        }
        String secret = params.get("secret");
        if (secret == null) {
            throw new IllegalArgumentException("otpauth URI has no secret");
        }
        String issuer = params.getOrDefault("issuer", "");
        int colon = label.indexOf(':');
        if (colon >= 0) {
            String labelIssuer = label.substring(0, colon).trim();
            if (!issuer.isEmpty() && !issuer.equals(labelIssuer)) {
                // Key URI format: the two must match. A mismatch is a classic sign of a
                // tampered or phishing QR code, so it is rejected rather than guessed.
                throw new IllegalArgumentException("issuer parameter '" + issuer
                        + "' does not match label prefix '" + labelIssuer + "'");
            }
            if (issuer.isEmpty()) {
                issuer = labelIssuer;
            }
            label = label.substring(colon + 1).trim();
        }
        int digits = Integer.parseInt(params.getOrDefault("digits", "6"));
        int period = Integer.parseInt(params.getOrDefault("period", "30"));
        Hotp.Algorithm algorithm = Hotp.Algorithm.parse(params.getOrDefault("algorithm", "SHA1"));
        return new Account(label, issuer, Base32.decode(secret), digits, period, algorithm);
    }

    public String toUri() {
        String name = issuer.isEmpty() ? label : issuer + ":" + label;
        return "otpauth://totp/" + encode(name)
                + "?secret=" + Base32.encode(secret).replace("=", "")
                + (issuer.isEmpty() ? "" : "&issuer=" + encode(issuer))
                + "&algorithm=" + algorithm.name()
                + "&digits=" + digits
                + "&period=" + period;
    }

    /** Overwrites this record's copy of the secret. Call when the account is no longer needed. */
    public void wipe() {
        Arrays.fill(secret, (byte) 0);
    }

    private static String decode(String s) {
        return URLDecoder.decode(s, StandardCharsets.UTF_8);
    }

    private static String encode(String s) {
        return URLEncoder.encode(s, StandardCharsets.UTF_8).replace("+", "%20");
    }
}
