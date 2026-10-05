package kaappu;

import java.io.BufferedReader;
import java.io.Console;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Command-line front end. Secrets and passwords are only ever read from a hidden
 * prompt, never from command-line arguments, which end up in shell history and in
 * the process list where other users on the machine can see them.
 */
public final class Main {

    private static final BufferedReader STDIN =
            new BufferedReader(new InputStreamReader(System.in, StandardCharsets.UTF_8));

    public static void main(String[] args) {
        if (args.length == 0 || args[0].equals("help") || args[0].equals("--help")) {
            usage();
            return;
        }
        try {
            run(args);
        } catch (IllegalArgumentException | IOException e) {
            System.err.println("kaappu: " + e.getMessage());
            System.exit(1);
        }
    }

    private static void run(String[] args) throws IOException {
        Path vaultPath = vaultPath();
        switch (args[0]) {
            case "init" -> {
                Files.createDirectories(vaultPath.toAbsolutePath().getParent());
                char[] pw = newPassword();
                try (Vault v = Vault.create(vaultPath, pw, Vault.DEFAULT_ITERATIONS)) {
                    System.out.println("Created " + vaultPath + " (" + v.accounts().size() + " accounts)");
                    System.out.println("Next: run 'kaappu backup 2 3' and hand the three shares to three different places.");
                } finally {
                    Arrays.fill(pw, '\0');
                }
            }
            case "add" -> withVault(vaultPath, v -> {
                char[] input = secretPrompt("Paste the otpauth:// URI or the Base32 secret: ");
                String text = new String(input).trim();
                Arrays.fill(input, '\0');
                Account a;
                if (text.startsWith("otpauth://")) {
                    a = Account.fromUri(text);
                } else {
                    String label = args.length > 1 ? args[1] : line("Label for this account: ");
                    a = Account.fromBase32(label, text);
                }
                if (a.isWeak()) {
                    System.err.println("Warning: this secret is under 128 bits, below RFC 4226's minimum. It still works.");
                }
                v.add(a);
                v.save();
                System.out.println("Added " + display(a));
            });
            case "list" -> withVault(vaultPath, v -> {
                if (v.accounts().isEmpty()) {
                    System.out.println("No accounts yet. Add one with 'kaappu add'.");
                }
                for (Account a : v.accounts()) {
                    System.out.println(display(a) + "  (" + a.algorithm() + ", " + a.digits() + " digits, " + a.period() + "s)");
                }
            });
            case "code" -> withVault(vaultPath, v -> {
                long now = Instant.now().getEpochSecond();
                boolean any = false;
                for (Account a : v.accounts()) {
                    if (args.length > 1 && !a.label().equalsIgnoreCase(args[1]) && !a.issuer().equalsIgnoreCase(args[1])) {
                        continue;
                    }
                    any = true;
                    System.out.printf("%-32s %s   %2ds left%n", display(a), group(Totp.at(a, now)), Totp.secondsRemaining(a, now));
                }
                if (!any) {
                    System.out.println(args.length > 1 ? "No account matches '" + args[1] + "'." : "No accounts yet.");
                }
            });
            case "remove" -> withVault(vaultPath, v -> {
                if (args.length < 2) throw new IllegalArgumentException("usage: kaappu remove <label>");
                if (!v.remove(args[1])) throw new IllegalArgumentException("no account labelled '" + args[1] + "'");
                v.save();
                System.out.println("Removed " + args[1]);
            });
            case "backup" -> withVault(vaultPath, v -> {
                if (args.length < 3) throw new IllegalArgumentException("usage: kaappu backup <threshold> <shares>, e.g. kaappu backup 2 3");
                int k = Integer.parseInt(args[1]);
                int n = Integer.parseInt(args[2]);
                Shamir.Share[] shares = v.backupShares(k, n);
                System.out.println("Any " + k + " of these " + n + " shares can open this vault without the password.");
                System.out.println("Store each one in a different place. Fewer than " + k + " reveal nothing.\n");
                for (Shamir.Share s : shares) {
                    System.out.println("  " + s.encode());
                }
                System.out.println("\nThe shares stay valid after a password change. To retire them, make a new vault.");
            });
            case "recover" -> {
                List<Shamir.Share> shares = new ArrayList<>();
                Shamir.Share first = Shamir.Share.decode(new String(secretPrompt("Share 1: ")));
                shares.add(first);
                for (int i = 2; i <= first.threshold(); i++) {
                    shares.add(Shamir.Share.decode(new String(secretPrompt("Share " + i + ": "))));
                }
                try (Vault v = Vault.openWithShares(vaultPath, shares)) {
                    System.out.println("Shares accepted. " + v.accounts().size() + " account(s) recovered. Choose a new password.");
                    char[] pw = newPassword();
                    try {
                        v.changePassword(pw);
                    } finally {
                        Arrays.fill(pw, '\0');
                    }
                    System.out.println("Done. The vault now opens with the new password.");
                }
            }
            case "passwd" -> withVault(vaultPath, v -> {
                char[] pw = newPassword();
                try {
                    v.changePassword(pw);
                } finally {
                    Arrays.fill(pw, '\0');
                }
                System.out.println("Password changed. Existing backup shares still work.");
            });
            default -> {
                usage();
                System.exit(2);
            }
        }
    }

    private interface VaultAction {
        void run(Vault v) throws IOException;
    }

    private static void withVault(Path path, VaultAction action) throws IOException {
        if (!Files.exists(path)) {
            throw new IOException("no vault at " + path + ". Run 'kaappu init' first.");
        }
        char[] pw = secretPrompt("Vault password: ");
        try (Vault v = Vault.open(path, pw)) {
            Arrays.fill(pw, '\0');
            action.run(v);
        } finally {
            Arrays.fill(pw, '\0');
        }
    }

    private static Path vaultPath() {
        String env = System.getenv("KAAPPU_VAULT");
        return env != null && !env.isBlank()
                ? Path.of(env)
                : Path.of(System.getProperty("user.home"), ".kaappu", "vault.kpu");
    }

    private static char[] newPassword() throws IOException {
        while (true) {
            char[] a = secretPrompt("New vault password (12+ characters): ");
            if (a.length < 12) {
                System.err.println("Too short. A passphrase of four or five random words works well.");
                Arrays.fill(a, '\0');
                continue;
            }
            char[] b = secretPrompt("Repeat it: ");
            boolean same = Arrays.equals(a, b);
            Arrays.fill(b, '\0');
            if (same) return a;
            Arrays.fill(a, '\0');
            System.err.println("They did not match. Try again.");
        }
    }

    /** Hidden input on a terminal; plain stdin when piped (for scripts and tests). */
    private static char[] secretPrompt(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) {
            char[] value = console.readPassword(prompt);
            if (value == null) throw new IOException("input closed");
            return value;
        }
        System.err.print(prompt);
        String l = STDIN.readLine();
        if (l == null) throw new IOException("input closed");
        return l.toCharArray();
    }

    private static String line(String prompt) throws IOException {
        Console console = System.console();
        if (console != null) return console.readLine(prompt);
        System.err.print(prompt);
        return STDIN.readLine();
    }

    private static String display(Account a) {
        return a.issuer().isEmpty() ? a.label() : a.issuer() + " (" + a.label() + ")";
    }

    private static String group(String code) {
        int half = code.length() / 2;
        return code.substring(0, half) + " " + code.substring(half);
    }

    private static void usage() {
        System.out.println("""
                kaappu - a TOTP authenticator you can't lose

                  kaappu init                 create an encrypted vault
                  kaappu add [label]          add an account (secret is read from a hidden prompt)
                  kaappu code [name]          show current codes
                  kaappu list                 list accounts
                  kaappu remove <label>       delete an account
                  kaappu backup <k> <n>       split the vault key into n shares, any k of which recover it
                  kaappu recover              open the vault with k shares and set a new password
                  kaappu passwd               change the vault password

                Vault: ~/.kaappu/vault.kpu (override with KAAPPU_VAULT)""");
    }
}
