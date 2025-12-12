/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.PrivateKey;
import java.security.PublicKey;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class KeyWrapUtil {
    
    
    public static byte[] wrapKey(SecretKey aesKey, PublicKey publicKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(aesKey.getEncoded());
    }

    public static SecretKey unwrapKey(byte[] wrappedKey, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] keyBytes = cipher.doFinal(wrappedKey);
        return new SecretKeySpec(keyBytes, "AES");
    }
}
