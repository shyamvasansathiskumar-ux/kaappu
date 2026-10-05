package kaappu;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.security.GeneralSecurityException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

/**
 * The encrypted file that holds every account.
 *
 * Two keys, so the backup shares never depend on the password:
 *   data key      random 256 bits; encrypts the account list with AES-256-GCM
 *   password key  PBKDF2-HMAC-SHA256 of the password; wraps (encrypts) the data key
 *
 * Shamir shares are taken of the data key. Forget the password and k shares still
 * open the vault; change the password and old shares keep working, because only the
 * wrapping changes.
 *
 * File layout (all integers big-endian):
 *   "KAAPPU" | version (1) | iterations (4) | salt (16) | wrap IV (12) | wrapped key (48)
 *   | data IV (12) | ciphertext + GCM tag
 * Everything before the ciphertext is passed to GCM as associated data, so changing
 * the iteration count or swapping in another file's header breaks decryption.
 */
public final class Vault implements AutoCloseable {

    private static final byte[] MAGIC = "KAAPPU".getBytes(StandardCharsets.US_ASCII);
    private static final byte VERSION = 1;
    /** OWASP Password Storage Cheat Sheet figure for PBKDF2-HMAC-SHA256. */
    public static final int DEFAULT_ITERATIONS = 600_000;
    private static final int SALT_LEN = 16;
    private static final int IV_LEN = 12;
    private static final int KEY_LEN = 32;
    private static final int TAG_BITS = 128;
    private static final SecureRandom RANDOM = new SecureRandom();

    private final Path path;
    private final byte[] dataKey;
    private final List<Account> accounts;
    private int iterations;
    private byte[] salt;
    private byte[] wrapIv;
    private byte[] wrappedKey;

    private Vault(Path path, byte[] dataKey, List<Account> accounts, int iterations,
                  byte[] salt, byte[] wrapIv, byte[] wrappedKey) {
        this.path = path;
        this.dataKey = dataKey;
        this.accounts = accounts;
        this.iterations = iterations;
        this.salt = salt;
        this.wrapIv = wrapIv;
        this.wrappedKey = wrappedKey;
    }

    public static Vault create(Path path, char[] password, int iterations) throws IOException {
        if (Files.exists(path)) {
            throw new IOException("a vault already exists at " + path + "; refusing to overwrite it");
        }
        byte[] dataKey = random(KEY_LEN);
        Vault vault = new Vault(path, dataKey, new ArrayList<>(), iterations, null, null, null);
        vault.rewrap(password, iterations);
        vault.save();
        return vault;
    }

    public static Vault open(Path path, char[] password) throws IOException {
        Parsed p = Parsed.read(path);
        byte[] passwordKey = deriveKey(password, p.salt, p.iterations);
        byte[] dataKey;
        try {
            dataKey = aesGcm(Cipher.DECRYPT_MODE, passwordKey, p.wrapIv, p.wrappedKey, p.wrapAad());
        } catch (AEADBadTagException e) {
            throw new IOException("wrong password, or the vault file has been modified");
        } finally {
            Arrays.fill(passwordKey, (byte) 0);
        }
        return p.unlock(path, dataKey);
    }

    /** Opens the vault with backup shares instead of the password. */
    public static Vault openWithShares(Path path, List<Shamir.Share> shares) throws IOException {
        Parsed p = Parsed.read(path);
        byte[] dataKey = Shamir.combine(shares);
        return p.unlock(path, dataKey);
    }

    public List<Account> accounts() {
        return Collections.unmodifiableList(accounts);
    }

    public void add(Account account) {
        for (Account a : accounts) {
            if (a.label().equals(account.label()) && a.issuer().equals(account.issuer())) {
                throw new IllegalArgumentException("an account named '" + account.label() + "' already exists");
            }
        }
        accounts.add(account);
    }

    public boolean remove(String label) {
        for (int i = 0; i < accounts.size(); i++) {
            if (accounts.get(i).label().equals(label)) {
                accounts.remove(i).wipe();
                return true;
            }
        }
        return false;
    }

    /** Splits the data key, not the password, so the shares survive a password change. */
    public Shamir.Share[] backupShares(int threshold, int count) {
        return Shamir.split(dataKey, threshold, count);
    }

    /** Re-encrypts the data key under a new password. Old backup shares keep working. */
    public void changePassword(char[] newPassword) throws IOException {
        rewrap(newPassword, iterations);
        save();
    }

    public void save() throws IOException {
        byte[] header = header();
        byte[] dataIv = random(IV_LEN);
        byte[] aad = concat(header, dataIv);
        byte[] plaintext = serialize(accounts);
        byte[] ciphertext;
        try {
            ciphertext = aesGcm(Cipher.ENCRYPT_MODE, dataKey, dataIv, plaintext, aad);
        } catch (AEADBadTagException e) {
            throw new IllegalStateException(e);
        } finally {
            Arrays.fill(plaintext, (byte) 0);
        }
        // Write to a temporary file and move it into place, so a crash or a full disk
        // mid-write can never leave a half-written vault in place of the good one.
        Path tmp = path.resolveSibling(path.getFileName() + ".tmp");
        Files.write(tmp, concat(aad, ciphertext));
        restrictToOwner(tmp);
        try {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        } catch (AtomicMoveNotSupportedException e) {
            Files.move(tmp, path, StandardCopyOption.REPLACE_EXISTING);
        }
    }

    @Override
    public void close() {
        Arrays.fill(dataKey, (byte) 0);
        for (Account a : accounts) {
            a.wipe();
        }
    }

    private void rewrap(char[] password, int iterations) {
        this.iterations = iterations;
        this.salt = random(SALT_LEN);
        this.wrapIv = random(IV_LEN);
        byte[] passwordKey = deriveKey(password, salt, iterations);
        try {
            this.wrappedKey = aesGcm(Cipher.ENCRYPT_MODE, passwordKey, wrapIv, dataKey, wrapAad(iterations, salt));
        } catch (AEADBadTagException e) {
            throw new IllegalStateException(e);
        } finally {
            Arrays.fill(passwordKey, (byte) 0);
        }
    }

    private byte[] header() {
        return concat(wrapAad(iterations, salt), wrapIv, wrappedKey);
    }

    private static byte[] wrapAad(int iterations, byte[] salt) {
        return concat(MAGIC, new byte[] {VERSION}, ByteBuffer.allocate(4).putInt(iterations).array(), salt);
    }

    static byte[] deriveKey(char[] password, byte[] salt, int iterations) {
        if (iterations < 100_000) {
            throw new IllegalArgumentException("PBKDF2 iterations below 100,000 are too fast to slow down guessing");
        }
        PBEKeySpec spec = new PBEKeySpec(password, salt, iterations, KEY_LEN * 8);
        try {
            return SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256").generateSecret(spec).getEncoded();
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        } finally {
            spec.clearPassword();
        }
    }

    private static byte[] aesGcm(int mode, byte[] key, byte[] iv, byte[] input, byte[] aad) throws AEADBadTagException {
        try {
            Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
            cipher.init(mode, new SecretKeySpec(key, "AES"), new GCMParameterSpec(TAG_BITS, iv));
            cipher.updateAAD(aad);
            return cipher.doFinal(input);
        } catch (AEADBadTagException e) {
            throw e;
        } catch (GeneralSecurityException e) {
            throw new IllegalStateException(e);
        }
    }

    private static byte[] serialize(List<Account> accounts) {
        StringBuilder sb = new StringBuilder();
        for (Account a : accounts) {
            sb.append(a.label()).append('\t')
              .append(a.issuer()).append('\t')
              .append(Base32.encode(a.secret())).append('\t')
              .append(a.digits()).append('\t')
              .append(a.period()).append('\t')
              .append(a.algorithm().name()).append('\n');
        }
        return sb.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static List<Account> deserialize(byte[] data) {
        List<Account> out = new ArrayList<>();
        for (String line : new String(data, StandardCharsets.UTF_8).split("\n")) {
            if (line.isEmpty()) continue;
            String[] f = line.split("\t", -1);
            out.add(new Account(f[0], f[1], Base32.decode(f[2]), Integer.parseInt(f[3]),
                    Integer.parseInt(f[4]), Hotp.Algorithm.parse(f[5])));
        }
        return out;
    }

    /** Owner read/write only (chmod 600) where the file system supports POSIX permissions. */
    private static void restrictToOwner(Path file) {
        try {
            Files.setPosixFilePermissions(file, java.nio.file.attribute.PosixFilePermissions.fromString("rw-------"));
        } catch (UnsupportedOperationException | IOException e) {
            // Windows and some mounted drives: nothing to do; the contents are encrypted anyway.
        }
    }

    private static byte[] random(int n) {
        byte[] b = new byte[n];
        RANDOM.nextBytes(b);
        return b;
    }

    private static byte[] concat(byte[]... parts) {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        for (byte[] p : parts) {
            out.writeBytes(p);
        }
        return out.toByteArray();
    }

    /** The file, read and split into fields, before anything is decrypted. */
    private record Parsed(int iterations, byte[] salt, byte[] wrapIv, byte[] wrappedKey,
                          byte[] dataIv, byte[] ciphertext) {

        static Parsed read(Path path) throws IOException {
            byte[] all = Files.readAllBytes(path);
            try (DataInputStream in = new DataInputStream(new java.io.ByteArrayInputStream(all))) {
                byte[] magic = in.readNBytes(MAGIC.length);
                if (!Arrays.equals(magic, MAGIC)) {
                    throw new IOException("not a kaappu vault: " + path);
                }
                int version = in.readUnsignedByte();
                if (version != VERSION) {
                    throw new IOException("unsupported vault version " + version);
                }
                int iterations = in.readInt();
                byte[] salt = in.readNBytes(SALT_LEN);
                byte[] wrapIv = in.readNBytes(IV_LEN);
                byte[] wrappedKey = in.readNBytes(KEY_LEN + TAG_BITS / 8);
                byte[] dataIv = in.readNBytes(IV_LEN);
                byte[] ciphertext = in.readAllBytes();
                if (dataIv.length != IV_LEN || ciphertext.length < TAG_BITS / 8) {
                    throw new IOException("vault file is truncated");
                }
                return new Parsed(iterations, salt, wrapIv, wrappedKey, dataIv, ciphertext);
            }
        }

        byte[] wrapAad() {
            return Vault.wrapAad(iterations, salt);
        }

        Vault unlock(Path path, byte[] dataKey) throws IOException {
            byte[] aad = concat(wrapAad(), wrapIv, wrappedKey, dataIv);
            byte[] plaintext;
            try {
                plaintext = aesGcm(Cipher.DECRYPT_MODE, dataKey, dataIv, ciphertext, aad);
            } catch (AEADBadTagException e) {
                Arrays.fill(dataKey, (byte) 0);
                throw new IOException("could not decrypt the vault: wrong shares, or the file has been modified");
            }
            List<Account> accounts = deserialize(plaintext);
            Arrays.fill(plaintext, (byte) 0);
            return new Vault(path, dataKey, accounts, iterations, salt, wrapIv, wrappedKey);
        }
    }
}
