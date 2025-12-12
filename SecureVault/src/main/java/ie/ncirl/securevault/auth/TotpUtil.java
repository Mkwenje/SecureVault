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

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

/**
 *
 * @author Mkwenje Tadiwa
 */
/**
 * TotpUtil
 *
 * Utility class for generating and verifying Time-based One-Time Passwords (TOTP).
 * TOTP is defined in RFC 6238 and builds on the HOTP algorithm from RFC 4226.
 *
 * The code here follows the algorithm described in those RFCs:
 *  - Shared secret key (Base32 encoded)
 *  - 30-second time steps
 *  - HMAC-SHA1 over an 8-byte counter
 *  - Dynamic truncation to produce a 6-digit code
 *
 * You should reference RFC 6238 in your documentation to acknowledge
 * that the algorithm is not original to this project.
 */
public class TotpUtil {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final int SECRET_LENGTH = 20;      // 160-bit secret key
    private static final int TIME_STEP_SECONDS = 30;  // standard TOTP time window
    private static final String HMAC_ALGO = "HmacSHA1";

    /**
     * Generates a random Base32-encoded secret, suitable for use with apps like
     * Google Authenticator or Authy.
     */
    public static String generateSecret() {
        byte[] buffer = new byte[SECRET_LENGTH];
        secureRandom.nextBytes(buffer);
        Base32 base32 = new Base32();
        return base32.encodeToString(buffer);
    }

    /**
     * Generates a 6-digit TOTP code for a given secret and point in time.
     *
     * @param base32Secret the shared secret encoded in Base32.
     * @param timeMillis   the time in milliseconds since epoch.
     * @return a 6-digit integer code.
     */
    public static int generateCode(String base32Secret, long timeMillis) {
        Base32 base32 = new Base32();
        byte[] key = base32.decode(base32Secret);

        // Convert current time into a 30-second "time step" value.
        long timeStep = (timeMillis / 1000L) / TIME_STEP_SECONDS;

        try {
            // Build an 8-byte array representing the time step counter.
            byte[] data = new byte[8];
            for (int i = 7; i >= 0; i--) {
                data[i] = (byte) (timeStep & 0xFF);
                timeStep >>= 8;
            }

            // Create HMAC-SHA1 of the counter using the secret key.
            SecretKeySpec signKey = new SecretKeySpec(key, HMAC_ALGO);
            Mac mac = Mac.getInstance(HMAC_ALGO);
            mac.init(signKey);
            byte[] hmac = mac.doFinal(data);

            // Dynamic truncation: take 4 bytes starting at an offset
            // indicated by the low 4 bits of the last byte.
            int offset = hmac[hmac.length - 1] & 0x0F;
            int binary =
                    ((hmac[offset] & 0x7f) << 24) |
                    ((hmac[offset + 1] & 0xff) << 16) |
                    ((hmac[offset + 2] & 0xff) << 8) |
                    (hmac[offset + 3] & 0xff);

            // Restrict to 6 digits.
            int otp = binary % 1_000_000;
            return otp;
        } catch (Exception e) {
            throw new RuntimeException("Error generating TOTP", e);
        }
    }

    /**
     * Verifies a user-entered TOTP code, allowing for a small amount of clock drift.
     *
     * @param base32Secret      the Base32-encoded shared secret.
     * @param code              the 6-digit user-entered code.
     * @param allowedDriftSteps how many 30-second windows before/after to accept.
     * @return true if the code is valid within the allowed drift, false otherwise.
     */
    public static boolean verifyCode(String base32Secret, int code, int allowedDriftSteps) {
        long now = Instant.now().toEpochMilli();

        // Check codes for [now - drift, now + drift] time windows.
        for (int i = -allowedDriftSteps; i <= allowedDriftSteps; i++) {
            long time = now + (i * TIME_STEP_SECONDS * 1000L);
            int candidate = generateCode(base32Secret, time);
            if (candidate == code) {
                return true;
            }
        }
        return false;
    }
    
        /**
     * Builds an otpauth:// URL that can be encoded as a QR code and scanned
     * by authenticator apps such as "Authenticator App - SafeAuth".
     *
     * This follows the Key URI Format defined by Google for TOTP:
     * https://github.com/google/google-authenticator/wiki/Key-Uri-Format
     *
     * @param accountName the username or account identifier
     * @param issuer the name of the application (e.g. SecureVault)
     * @param secretBase32 the Base32-encoded TOTP secret
     * @return otpauth URL string
     */
    public static String buildOtpAuthUrl(String accountName, String issuer, String secretBase32) {
        try {
            String label = URLEncoder.encode(issuer + ":" + accountName, "UTF-8");
            String issuerEncoded = URLEncoder.encode(issuer, "UTF-8");

            return "otpauth://totp/" + label +
                   "?secret=" + secretBase32 +
                   "&issuer=" + issuerEncoded +
                   "&algorithm=SHA1&digits=6&period=30";
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException("UTF-8 encoding not supported", e);
        }
    }
}