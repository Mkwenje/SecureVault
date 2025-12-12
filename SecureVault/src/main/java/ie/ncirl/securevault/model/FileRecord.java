/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.model;


/**
 * FileRecord
 *
 * Represents an encrypted file entry stored in the database.
 * Includes metadata about the file and the wrapped AES key
 * used for secure decryption.
 *
 * @author Mkwenje Tadiwa
 */
public class FileRecord {

    private int id;
    private int userId;
    private String originalPath;
    private String encryptedPath;

    // Wrapped AES key (encrypted using RSA public key)
    private byte[] wrappedKey;

    public FileRecord() {}

    public FileRecord(int id, int userId, String originalPath, String encryptedPath, byte[] wrappedKey) {
        this.id = id;
        this.userId = userId;
        this.originalPath = originalPath;
        this.encryptedPath = encryptedPath;
        this.wrappedKey = wrappedKey;
    }

    public int getId() { return id; }
    public int getUserId() { return userId; }
    public String getOriginalPath() { return originalPath; }
    public String getEncryptedPath() { return encryptedPath; }

    // Getter for wrapped AES key
    public byte[] getWrappedKey() { return wrappedKey; }

    public void setId(int id) { this.id = id; }
    public void setUserId(int userId) { this.userId = userId; }
    public void setOriginalPath(String originalPath) { this.originalPath = originalPath; }
    public void setEncryptedPath(String encryptedPath) { this.encryptedPath = encryptedPath; }

    // Setter for wrapped AES key
    public void setWrappedKey(byte[] wrappedKey) { this.wrappedKey = wrappedKey; }
}
