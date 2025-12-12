/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class AesGcmCrypto {
    
        private static final int AES_BITS = 256;
    private static final int IV_BYTES = 12;          // recommended for GCM
    private static final int TAG_BITS = 128;         // 16 bytes auth tag

    private static final SecureRandom random = new SecureRandom();

    public static SecretKey generateKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_BITS);
        return kg.generateKey();
    }

    public static void encryptFile(Path input, Path output, SecretKey key) throws Exception {
        byte[] iv = new byte[IV_BYTES];
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));

        byte[] plaintext = Files.readAllBytes(input);
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Write: [IV length (1 byte)] [IV bytes] [ciphertext+tag]
        byte[] out = new byte[1 + iv.length + ciphertext.length];
        out[0] = (byte) iv.length;
        System.arraycopy(iv, 0, out, 1, iv.length);
        System.arraycopy(ciphertext, 0, out, 1 + iv.length, ciphertext.length);

        Files.write(output, out);
    }

    public static void decryptFile(Path input, Path output, SecretKey key) throws Exception {
        byte[] all = Files.readAllBytes(input);

        int ivLen = all[0] & 0xFF;
        byte[] iv = new byte[ivLen];
        System.arraycopy(all, 1, iv, 0, ivLen);

        byte[] ciphertext = new byte[all.length - 1 - ivLen];
        System.arraycopy(all, 1 + ivLen, ciphertext, 0, ciphertext.length);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(TAG_BITS, iv));

        byte[] plaintext = cipher.doFinal(ciphertext);
        Files.write(output, plaintext);
    }
}
