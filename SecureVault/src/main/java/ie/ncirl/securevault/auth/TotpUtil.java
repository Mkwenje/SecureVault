/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.auth;

import org.apache.commons.codec.binary.Base32;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.time.Instant;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class TotpUtil {
    
     private static final SecureRandom secureRandom = new SecureRandom();
    private static final int SECRET_LENGTH = 20; // bytes
    private static final int TIME_STEP_SECONDS = 30;
    private static final String HMAC_ALGO = "HmacSHA1"; // standard for TOTP

    // Generate a random Base32-encoded secret, to be stored per user
    public static String generateSecret() {
        byte[] buffer = new byte[SECRET_LENGTH];
        secureRandom.nextBytes(buffer);
        Base32 base32 = new Base32();
        return base32.encodeToString(buffer);
    }

    // Generate a 6-digit TOTP code for given secret & time
    public static int generateCode(String base32Secret, long timeMillis) {
        Base32 base32 = new Base32();
        byte[] key = base32.decode(base32Secret);

        long timeStep = (timeMillis / 1000L) / TIME_STEP_SECONDS;

        try {
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (timeStep & 0xFF);
                timeStep >>= 8;
            }

            SecretKeySpec signKey = new SecretKeySpec(key, HMAC_ALGO);
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(signKey);
            byte[] hmac = mac.doFinal(data);

            int offset = hmac[hmac.length - 1] & 0x0F;
            int binary =
                    ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);

            int otp = binary % 1_000_000; // 6 digits
            return otp;
        } catch (Exception e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    // Verify a user-entered code, allowing for small clock drift
    public static boolean verifyCode(String base32Secret, int code, int allowedDriftSteps) {
        long now = Instant.now().toEpochMilli();

        for (int i = -allowedDriftSteps; i <= allowedDriftSteps; i++) {
            long time = now + (i * TIME_STEP_SECONDS * 1000L);
            int candidate = generateCode(base32Secret, time);
            if (candidate == code) {
                return true;
            }
        }
        return false;
    }
    
}
