package kaappu;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

/**
 * TOTP, RFC 6238: HOTP where the counter is the number of time steps since T0.
 */
public final class Totp {

    public static final int DEFAULT_PERIOD = 30;

    private Totp() {}

    public static long timeStep(long epochSeconds, int periodSeconds) {
        if (periodSeconds <= 0) {
            throw new IllegalArgumentException("period must be positive");
        }
        // Math.floorDiv keeps the step correct for times before 1970 as well.
        return Math.floorDiv(epochSeconds, periodSeconds);
    }

    public static String at(Account account, long epochSeconds) {
        long step = timeStep(epochSeconds, account.period());
        return Hotp.generate(account.secret(), step, account.digits(), account.algorithm());
    }

    public static int secondsRemaining(Account account, long epochSeconds) {
        return account.period() - (int) Math.floorMod(epochSeconds, (long) account.period());
    }

    /**
     * A server-side check with the two protections RFC 6238 section 5.2 asks for:
     * a small window for clock drift, and refusing any time step already used,
     * so a code read over someone's shoulder cannot be replayed within its 30 seconds.
     */
    public static final class Verifier {
        private final Account account;
        private final int driftSteps;
        private long lastAcceptedStep = Long.MIN_VALUE;

        public Verifier(Account account, int driftSteps) {
            if (driftSteps < 0 || driftSteps > 2) {
                throw new IllegalArgumentException("drift window should be 0 to 2 steps");
            }
            this.account = account;
            this.driftSteps = driftSteps;
        }

        public Result verify(String candidate, long epochSeconds) {
            if (candidate == null || candidate.length() != account.digits()) {
                return Result.REJECTED;
            }
            long now = timeStep(epochSeconds, account.period());
            byte[] given = candidate.getBytes(StandardCharsets.US_ASCII);
            boolean matched = false;
            long matchedStep = 0;
            // Every step in the window is checked even after a match, so the time
            // taken does not reveal which step matched.
            for (long step = now - driftSteps; step <= now + driftSteps; step++) {
                byte[] expected = Hotp.generate(account.secret(), step, account.digits(), account.algorithm())
                        .getBytes(StandardCharsets.US_ASCII);
                if (MessageDigest.isEqual(expected, given) && !matched) {
                    matched = true;
                    matchedStep = step;
                }
            }
            if (!matched) {
                return Result.REJECTED;
            }
            if (matchedStep <= lastAcceptedStep) {
                return Result.REPLAYED;
            }
            lastAcceptedStep = matchedStep;
            return Result.ACCEPTED;
        }
    }

    public enum Result { ACCEPTED, REJECTED, REPLAYED }
}
