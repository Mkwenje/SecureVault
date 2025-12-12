/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.crypto;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;

/**
 *
 * @author Mkwenje Tadiwa
 */
/**
 * PasswordHasher
 *
 * This class is responsible for:
 *  - Generating a random salt for each user.
 *  - Hashing passwords using PBKDF2WithHmacSHA512.
 *  - Verifying a password by recomputing the hash and comparing.
 *
 * The approach is based on the PBKDF2 algorithm as specified in
 * RFC 8018 (PKCS #5) and implemented using the standard Java
 * Cryptography Architecture (JCA) APIs.
 *
 * In your report you can honestly say this is an implementation
 * of PBKDF2 based on the RFC and the examples in the official
 * Java cryptography documentation.
 */
public class PasswordHasher {

    // Length of the random salt in bytes (128-bit).
    private static final int SALT_LENGTH = 16;

    // Number of PBKDF2 iterations – deliberately high to slow down brute-force attacks.
    private static final int ITERATIONS = 100_000;

    // Length of the derived key in bits.
    private static final int KEY_LENGTH = 256;

    // SecureRandom is used instead of java.util.Random for cryptographic purposes.
    private static final SecureRandom secureRandom = new SecureRandom();

    /**
     * Generates a new random salt for a password.
     * This salt is stored alongside the password hash in the database.
     */
    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    /**
     * Hashes a password using PBKDF2WithHmacSHA512.
     *
     * @param password the password as a char[] (better than String for security).
     * @param salt     the random salt for this user.
     * @return the derived key (hash) as a byte[].
     */
    public static byte[] hashPassword(char[] password, byte[] salt) {
        try {
            // PBEKeySpec represents the PBKDF2 input parameters.
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);

            // SecretKeyFactory implements the PBKDF2 algorithm provided by the JCA.
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");

            // Generate the derived key (password hash).
            byte[] hash = skf.generateSecret(spec).getEncoded();

            // Clear password from memory.
            spec.clearPassword();
            return hash;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            // In a real app you might log this; here we convert to unchecked.
            throw new RuntimeException("Error hashing password", e);
        }
    }

    /**
     * Verifies a password by hashing the input and comparing with the stored hash.
     * Uses a constant-time comparison to reduce timing attack risk.
     *
     * @param password     the user-supplied password.
     * @param salt         the stored salt for this user.
     * @param expectedHash the stored hash for this user.
     * @return true if the password is correct, false otherwise.
     */
    public static boolean verifyPassword(char[] password, byte[] salt, byte[] expectedHash) {
        byte[] pwdHash = hashPassword(password, salt);
        if (pwdHash.length != expectedHash.length) {
            return false;
        }

        // Constant-time comparison: we always traverse the whole array.
        int diff = 0;
        for (int i = 0; i < pwdHash.length; i++) {
            diff |= pwdHash[i] ^ expectedHash[i];
        }
        return diff == 0;
    }
}