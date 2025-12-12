/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.ui;


import ie.ncirl.securevault.auth.AuthService;
import ie.ncirl.securevault.crypto.AesGcmCrypto;
import ie.ncirl.securevault.crypto.KeyWrapUtil;
import ie.ncirl.securevault.db.FileRecordDao;
import ie.ncirl.securevault.logging.AuditLogger;
import ie.ncirl.securevault.model.FileRecord;

import javax.crypto.SecretKey;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.List;

/**
 * VaultDashboardFrame
 *
 * Main dashboard after login.
 * Shows a file list and provides Encrypt/Decrypt actions.
 *
 * Enhancement:
 *  - "Delete original after encryption" checkbox (optional plaintext removal)
 *
 *  - Encrypt file using AES-GCM
 *  - Wrap AES key using user's RSA public key (RSA-OAEP)
 *  - Store wrapped key in DB
 *
 *  - Load wrapped AES key from DB
 *  - Unwrap AES key using user's RSA private key (RSA-OAEP)
 *  - Decrypt file using AES-GCM
 *
 * Extra UX improvement:
 *  - Suggest decrypted filename based on original name
 *  - Ask user if they want to open the decrypted file automatically
 */
public class VaultDashboardFrame extends JFrame {

    private final String username;
    private int userId;

    private final AuthService authService = new AuthService();
    private final FileRecordDao fileDao = new FileRecordDao();

    private final JCheckBox deleteOriginalCheck = new JCheckBox("Delete original after encryption");

    private final DefaultTableModel tableModel = new DefaultTableModel(
            new String[]{"ID", "Original Path", "Encrypted Path"}, 0
    );
    private final JTable table = new JTable(tableModel);

    public VaultDashboardFrame(String username) {
        this.username = username;

        setTitle("SecureVault - Dashboard");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(900, 420);
        setLocationRelativeTo(null);

        JLabel welcome = new JLabel("Welcome, " + username + "!", SwingConstants.LEFT);
        welcome.setFont(welcome.getFont().deriveFont(Font.BOLD, 16f));

        JButton encryptBtn = new JButton("Encrypt File");
        JButton decryptBtn = new JButton("Decrypt Selected");
        JButton refreshBtn = new JButton("Refresh");
        JButton logoutBtn = new JButton("Logout");

        JPanel top = new JPanel(new BorderLayout());
        top.add(welcome, BorderLayout.WEST);

        JPanel buttons = new JPanel();
        buttons.add(deleteOriginalCheck);
        buttons.add(encryptBtn);
        buttons.add(decryptBtn);
        buttons.add(refreshBtn);
        buttons.add(logoutBtn);

        top.add(buttons, BorderLayout.EAST);

        add(top, BorderLayout.NORTH);
        add(new JScrollPane(table), BorderLayout.CENTER);

        encryptBtn.addActionListener(e -> encryptFileFlow());
        decryptBtn.addActionListener(e -> decryptSelectedFlow());
        refreshBtn.addActionListener(e -> refreshTable());
        logoutBtn.addActionListener(e -> {
            AuditLogger.log("LOGOUT", username, "User logged out");
            new LoginFrame().setVisible(true);
            dispose();
        });

        try {
            userId = authService.getUserId(username);
            refreshTable();
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Dashboard error: " + ex.getMessage());
        }
    }

    private void refreshTable() {
        try {
            tableModel.setRowCount(0);
            List<FileRecord> files = fileDao.getByUserId(userId);
            for (FileRecord fr : files) {
                tableModel.addRow(new Object[]{fr.getId(), fr.getOriginalPath(), fr.getEncryptedPath()});
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Refresh error: " + ex.getMessage());
        }
    }

    /**
     * Encrypt + RSA wrap AES key + store wrapped key
     */
    private void encryptFileFlow() {
        try {
            JFileChooser chooser = new JFileChooser();
            chooser.setDialogTitle("Select a file to encrypt");
            int result = chooser.showOpenDialog(this);
            if (result != JFileChooser.APPROVE_OPTION) return;

            Path input = chooser.getSelectedFile().toPath();

            JFileChooser saveChooser = new JFileChooser();
            saveChooser.setDialogTitle("Save encrypted file as...");
            saveChooser.setSelectedFile(new java.io.File(input.getFileName().toString() + ".sv"));
            int saveResult = saveChooser.showSaveDialog(this);
            if (saveResult != JFileChooser.APPROVE_OPTION) return;

            Path output = saveChooser.getSelectedFile().toPath();

            // Generate per-file AES key (AES-256)
            SecretKey aesKey = AesGcmCrypto.generateKey();

            // Encrypt the file using AES-GCM
            AesGcmCrypto.encryptFile(input, output, aesKey);

            // Load user's RSA public key from DB
            PublicKey publicKey = authService.getUserPublicKey(userId);
            if (publicKey == null) {
                throw new Exception("User RSA public key not found. Register again or reset DB.");
            }

            // Wrap AES key using RSA-OAEP (secure key storage)
            byte[] wrappedKey = KeyWrapUtil.wrapKey(aesKey, publicKey);

            // Store record in DB including wrapped AES key
            fileDao.insert(userId, input.toString(), output.toString(), wrappedKey);

            AuditLogger.log("ENCRYPT_FILE", username,
                    "Encrypted " + input + " -> " + output + " (AES-GCM + RSA-wrapped key)");

            // Optional plaintext deletion
            if (deleteOriginalCheck.isSelected()) {
                int confirm = JOptionPane.showConfirmDialog(
                        this,
                        "Are you sure you want to delete the original file?\n\n" + input,
                        "Confirm delete",
                        JOptionPane.YES_NO_OPTION
                );

                if (confirm == JOptionPane.YES_OPTION) {
                    try {
                        Files.deleteIfExists(input);
                        AuditLogger.log("PLAINTEXT_DELETED", username, "Deleted original: " + input);
                    } catch (Exception ex) {
                        AuditLogger.log("PLAINTEXT_DELETE_FAIL", username, ex.getMessage());
                        JOptionPane.showMessageDialog(this, "Could not delete original file: " + ex.getMessage());
                    }
                }
            }

            JOptionPane.showMessageDialog(this, "✅ File encrypted successfully!");
            refreshTable();

        } catch (Exception ex) {
            AuditLogger.log("ENCRYPT_FAIL", username, ex.getMessage());
            JOptionPane.showMessageDialog(this, "Encrypt error: " + ex.getMessage());
        }
    }

    /**
     * Decrypt selected + load wrapped key + RSA unwrap AES key + decrypt
     * (Improved: suggests decrypted filename + offers to open file)
     */
    private void decryptSelectedFlow() {
        int row = table.getSelectedRow();
        if (row == -1) {
            JOptionPane.showMessageDialog(this, "Select a file record first.");
            return;
        }

        int fileId = (int) tableModel.getValueAt(row, 0);
        String originalPathStr = (String) tableModel.getValueAt(row, 1);
        String encryptedPathStr = (String) tableModel.getValueAt(row, 2);

        try {
            Path encryptedPath = Path.of(encryptedPathStr);

            JFileChooser saveChooser = new JFileChooser();
            saveChooser.setDialogTitle("Save decrypted file as...");

            // ✅ Better default decrypted filename: OriginalName_decrypted.ext
            String originalName = java.nio.file.Path.of(originalPathStr).getFileName().toString();
            String decryptedName;
            int dot = originalName.lastIndexOf('.');
            if (dot != -1) {
                decryptedName = originalName.substring(0, dot) + "_decrypted" + originalName.substring(dot);
            } else {
                decryptedName = originalName + "_decrypted";
            }
            saveChooser.setSelectedFile(new java.io.File(decryptedName));

            int saveResult = saveChooser.showSaveDialog(this);
            if (saveResult != JFileChooser.APPROVE_OPTION) return;

            Path output = saveChooser.getSelectedFile().toPath();

            // Get wrapped AES key from DB
            byte[] wrappedKey = fileDao.getWrappedKeyById(fileId);
            if (wrappedKey == null || wrappedKey.length == 0) {
                throw new Exception("Wrapped key not found for this record.");
            }

            // Load user's RSA private key from DB
            PrivateKey privateKey = authService.getUserPrivateKey(userId);
            if (privateKey == null) {
                throw new Exception("User RSA private key not found. Register again or reset DB.");
            }

            // Unwrap AES key using RSA-OAEP
            SecretKey aesKey = KeyWrapUtil.unwrapKey(wrappedKey, privateKey);

            // Decrypt file using AES-GCM
            AesGcmCrypto.decryptFile(encryptedPath, output, aesKey);

            AuditLogger.log("DECRYPT_FILE", username,
                    "Decrypted " + encryptedPath + " -> " + output + " (RSA-unwrapped key + AES-GCM)");

            // ✅ Ask to open decrypted file
            int open = JOptionPane.showConfirmDialog(
                    this,
                    "✅ File decrypted successfully!\n\nOpen the decrypted file now?",
                    "Decryption Complete",
                    JOptionPane.YES_NO_OPTION
            );

            if (open == JOptionPane.YES_OPTION) {
                try {
                    Desktop.getDesktop().open(output.toFile());
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(this,
                            "Could not open file automatically:\n" + ex.getMessage());
                }
            }

        } catch (Exception ex) {
            AuditLogger.log("DECRYPT_FAIL", username, ex.getMessage());
            JOptionPane.showMessageDialog(this, "Decrypt error: " + ex.getMessage());
        }
    }
}