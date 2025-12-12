/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.auth;

import ie.ncirl.securevault.crypto.PasswordHasher;
import ie.ncirl.securevault.crypto.RsaKeyUtil;
import ie.ncirl.securevault.db.Database;
import ie.ncirl.securevault.model.User;

import java.sql.*;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * AuthService
 *
 * High-level service that handles:
 *  - User registration (creating a password hash, salt, and TOTP secret).
 *  - RSA keypair generation and storage (Step 8).
 *  - Looking up a user by username.
 *  - Verifying a login attempt using both password and TOTP code.
 */
public class AuthService {

    /**
     * Registers a new user.
     *  - Generates a new TOTP secret
     *  - Generates a salt and password hash using PBKDF2
     *  - Generates RSA key pair (public/private)
     *  - Stores everything in the database (including RSA keys)
     *
     * @return the created User object (with generated ID and secret).
     */
    public User register(String username, char[] password) throws SQLException {
        String totpSecret = TotpUtil.generateSecret();
        byte[] salt = PasswordHasher.generateSalt();
        byte[] hash = PasswordHasher.hashPassword(password, salt);

        // STEP 8: Generate RSA key pair for this user
        byte[] publicKeyBytes;
        byte[] privateKeyBytes;
        try {
            KeyPair kp = RsaKeyUtil.generateKeyPair();
            publicKeyBytes = kp.getPublic().getEncoded();   // X.509 format
            privateKeyBytes = kp.getPrivate().getEncoded(); // PKCS#8 format
        } catch (Exception e) {
            throw new SQLException("Failed to generate RSA keys", e);
        }

        try (Connection conn = Database.getConnection()) {
            String sql = """
                INSERT INTO users (username, password_hash, salt, totp_secret, public_key, private_key)
                VALUES (?, ?, ?, ?, ?, ?)
                """;

            try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, username);
                ps.setBytes(2, hash);
                ps.setBytes(3, salt);
                ps.setString(4, totpSecret);
                ps.setBytes(5, publicKeyBytes);
                ps.setBytes(6, privateKeyBytes);
                ps.executeUpdate();

                try (ResultSet rs = ps.getGeneratedKeys()) {
                    if (rs.next()) {
                        int id = rs.getInt(1);
                        return new User(id, username, hash, salt, totpSecret);
                    }
                }
            }
        }

        throw new SQLException("Failed to register user");
    }

    /**
     * Retrieves a user by username from the database.
     * (Does not load RSA keys into the User model - keys are fetched via separate methods.)
     */
    public User findByUsername(String username) throws SQLException {
        try (Connection conn = Database.getConnection()) {
            String sql = """
                SELECT id, username, password_hash, salt, totp_secret
                FROM users
                WHERE username = ?
                """;

            try (PreparedStatement ps = conn.prepareStatement(sql)) {
                ps.setString(1, username);
                try (ResultSet rs = ps.executeQuery()) {
                    if (rs.next()) {
                        return new User(
                                rs.getInt("id"),
                                rs.getString("username"),
                                rs.getBytes("password_hash"),
                                rs.getBytes("salt"),
                                rs.getString("totp_secret")
                        );
                    }
                }
            }
        }
        return null;
    }

    /**
     * Verifies a login attempt by:
     *  1. Fetching the user by username.
     *  2. Verifying the password using PBKDF2 hash comparison.
     *  3. Verifying the TOTP code using the stored secret.
     *
     * Both checks must pass for the login to succeed.
     */
    public boolean verifyLogin(String username, char[] password, int totpCode) throws SQLException {
        User user = findByUsername(username);
        if (user == null) {
            return false;
        }

        boolean pwdOk = PasswordHasher.verifyPassword(password, user.getSalt(), user.getPasswordHash());
        if (!pwdOk) {
            return false;
        }

        return TotpUtil.verifyCode(user.getTotpSecret(), totpCode, 1);
    }

    /**
     * Returns the user's database ID.
     */
    public int getUserId(String username) throws SQLException {
        User user = findByUsername(username);
        if (user == null) throw new SQLException("User not found");
        return user.getId();
    }

    /**
     * Fetches the user's RSA PublicKey from the database.
     * Used to wrap AES keys during encryption.
     */
    public PublicKey getUserPublicKey(int userId) throws SQLException {
        String sql = "SELECT public_key FROM users WHERE id = ?";

        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    byte[] keyBytes = rs.getBytes("public_key");
                    if (keyBytes == null) return null;

                    try {
                        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        return kf.generatePublic(spec);
                    } catch (Exception e) {
                        throw new SQLException("Failed to decode public key", e);
                    }
                }
            }
        }
        return null;
    }

    /**
     * Fetches the user's RSA PrivateKey from the database.
     * Used to unwrap AES keys during decryption.
     *
     * NOTE (for coursework): storing private keys in the DB is acceptable for demo,
     * but in a real system you would encrypt the private key or store it in a keystore.
     */
    public PrivateKey getUserPrivateKey(int userId) throws SQLException {
        String sql = "SELECT private_key FROM users WHERE id = ?";

        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    byte[] keyBytes = rs.getBytes("private_key");
                    if (keyBytes == null) return null;

                    try {
                        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
                        KeyFactory kf = KeyFactory.getInstance("RSA");
                        return kf.generatePrivate(spec);
                    } catch (Exception e) {
                        throw new SQLException("Failed to decode private key", e);
                    }
                }
            }
        }
        return null;
    }
}