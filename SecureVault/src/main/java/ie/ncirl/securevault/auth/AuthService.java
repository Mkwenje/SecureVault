/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.auth;

import ie.ncirl.securevault.crypto.PasswordHasher;
import ie.ncirl.securevault.db.Database;
import ie.ncirl.securevault.model.User;

import java.sql.*;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class AuthService {
    
        // Register a new user, returning the created User (with id + totpSecret)
    public User register(String username, char[] password) throws SQLException {
        String totpSecret = TotpUtil.generateSecret();
        byte[] salt = PasswordHasher.generateSalt();
        byte[] hash = PasswordHasher.hashPassword(password, salt);

        try (Connection conn = Database.getConnection()) {
            String sql = """
                INSERT INTO users (username, password_hash, salt, totp_secret)
                VALUES (?, ?, ?, ?)
                """;

            try (PreparedStatement ps = conn.prepareStatement(sql, Statement.RETURN_GENERATED_KEYS)) {
                ps.setString(1, username);
                ps.setBytes(2, hash);
                ps.setBytes(3, salt);
                ps.setString(4, totpSecret);
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

    // Verify both password AND TOTP code
    public boolean verifyLogin(String username, char[] password, int totpCode) throws SQLException {
        User user = findByUsername(username);
        if (user == null) {
            return false;
        }

        boolean pwdOk = PasswordHasher.verifyPassword(password, user.getSalt(), user.getPasswordHash());
        if (!pwdOk) {
            return false;
        }

        boolean totpOk = TotpUtil.verifyCode(user.getTotpSecret(), totpCode, 1);
        return totpOk;
    }

    
}
