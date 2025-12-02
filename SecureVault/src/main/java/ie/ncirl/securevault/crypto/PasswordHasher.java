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
public class PasswordHasher {
    
     private static final int SALT_LENGTH = 16;     // 128-bit salt
    private static final int ITERATIONS = 100_000; // adjust later if needed
    private static final int KEY_LENGTH = 256;     // bits

    private static final SecureRandom secureRandom = new SecureRandom();

    public static byte[] generateSalt() {
        byte[] salt = new byte[SALT_LENGTH];
        secureRandom.nextBytes(salt);
        return salt;
    }

    public static byte[] hashPassword(char[] password, byte[] salt) {
        try {
            PBEKeySpec spec = new PBEKeySpec(password, salt, ITERATIONS, KEY_LENGTH);
            SecretKeyFactory skf = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
            byte[] hash = skf.generateSecret(spec).getEncoded();
            spec.clearPassword();
            return hash;
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException("Error hashing password", e);
        }
    }

    public static boolean verifyPassword(char[] password, byte[] salt, byte[] expectedHash) {
        byte[] pwdHash = hashPassword(password, salt);
        if (pwdHash.length != expectedHash.length) {
            return false;
        }
        int diff = 0;
        for (int i = 0; i < pwdHash.length; i++) {
            diff |= pwdHash[i] ^ expectedHash[i];
        }
        return diff == 0;
    }
    
}
