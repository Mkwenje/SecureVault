/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.db;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;

/**
 * Database
 *
 * Centralised SQLite database manager.
 * Uses an absolute file path to ensure a single, consistent database.
 *
 * Database location:
 * C:\Users\Mkwenje Tadiwa\OneDrive\Documents\NetBeansProjects\SecureVault\securevault.db
 */
public class Database {

    // Absolute, fixed database path (NO more duplicate DB files)
    private static final Path DB_PATH = Paths.get(
            "C:\\Users\\Mkwenje Tadiwa\\OneDrive\\Documents\\NetBeansProjects\\SecureVault\\securevault.db"
    );

    private static final String URL = "jdbc:sqlite:" + DB_PATH.toAbsolutePath();

    /**
     * Returns a new connection to the SQLite database.
     */
    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(URL);
    }

    /**
     * Creates required tables and columns if they do not already exist.
     * Called once at application startup.
     */
    public static void initialize() throws SQLException {

        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement()) {

            // --- USERS TABLE ---
            String createUsers = """
                CREATE TABLE IF NOT EXISTS users (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password_hash BLOB NOT NULL,
                    salt BLOB NOT NULL,
                    totp_secret TEXT NOT NULL,
                    created_at DATETIME DEFAULT CURRENT_TIMESTAMP
                );
                """;

            stmt.execute(createUsers);

            // --- FILE RECORDS TABLE ---
            String createFiles = """
                CREATE TABLE IF NOT EXISTS file_records (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id INTEGER NOT NULL,
                    original_path TEXT NOT NULL,
                    encrypted_path TEXT NOT NULL,
                    date_encrypted DATETIME DEFAULT CURRENT_TIMESTAMP,
                    FOREIGN KEY (user_id) REFERENCES users(id)
                );
                """;

            stmt.execute(createFiles);

            // --- SAFE SCHEMA MIGRATIONS ---

            // Add RSA public key column to users table
            try {
                stmt.execute("ALTER TABLE users ADD COLUMN public_key BLOB;");
            } catch (SQLException ignored) {
                // Column already exists
            }

            // Add RSA private key column to users table
            try {
                stmt.execute("ALTER TABLE users ADD COLUMN private_key BLOB;");
            } catch (SQLException ignored) {
                // Column already exists
            }

            // Add wrapped AES key column to file_records table
            try {
                stmt.execute("ALTER TABLE file_records ADD COLUMN wrapped_key BLOB;");
            } catch (SQLException ignored) {
                // Column already exists
            }
        }

        // Helpful confirmation (can be removed later)
        System.out.println("USING DB FILE: " + DB_PATH.toAbsolutePath());
    }
}