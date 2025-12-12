/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.db;

import ie.ncirl.securevault.model.FileRecord;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

/**
 * FileRecordDao
 *
 * Handles database operations for encrypted file records.
 * Includes support for storing and retrieving wrapped AES keys.
 *
 * @author Mkwenje Tadiwa
 */
public class FileRecordDao {

    /**
     * 
     * Insert a new encrypted file record, including the wrapped AES key.
     */
    public void insert(int userId, String originalPath, String encryptedPath, byte[] wrappedKey)
            throws SQLException {

        String sql = """
            INSERT INTO file_records (user_id, original_path, encrypted_path, wrapped_key)
            VALUES (?, ?, ?, ?)
        """;

        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);
            ps.setString(2, originalPath);
            ps.setString(3, encryptedPath);
            ps.setBytes(4, wrappedKey);
            ps.executeUpdate();
        }
    }

    /**
     * Retrieves all encrypted file records for a given user.
     * (Wrapped key is not loaded here for performance reasons.)
     */
    public List<FileRecord> getByUserId(int userId) throws SQLException {

        String sql = """
            SELECT id, user_id, original_path, encrypted_path
            FROM file_records
            WHERE user_id = ?
            ORDER BY id DESC
        """;

        List<FileRecord> results = new ArrayList<>();

        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, userId);
            try (ResultSet rs = ps.executeQuery()) {
                while (rs.next()) {
                    results.add(new FileRecord(
                            rs.getInt("id"),
                            rs.getInt("user_id"),
                            rs.getString("original_path"),
                            rs.getString("encrypted_path"),
                            null // wrappedKey not loaded here
                    ));
                }
            }
        }
        return results;
    }

    /**
     * 
     * Retrieve the wrapped AES key for a specific file record.
     * Used during decryption.
     */
    public byte[] getWrappedKeyById(int fileId) throws SQLException {

        String sql = """
            SELECT wrapped_key
            FROM file_records
            WHERE id = ?
        """;

        try (Connection conn = Database.getConnection();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            ps.setInt(1, fileId);
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    return rs.getBytes("wrapped_key");
                }
            }
        }
        return null;
    }
}