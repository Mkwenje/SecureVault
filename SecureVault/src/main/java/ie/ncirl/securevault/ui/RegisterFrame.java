/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.ui;


import ie.ncirl.securevault.auth.AuthService;
import ie.ncirl.securevault.auth.QrCodeUtil;
import ie.ncirl.securevault.auth.TotpUtil;
import ie.ncirl.securevault.model.User;
import ie.ncirl.securevault.logging.AuditLogger;

import javax.swing.*;
import java.awt.*;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class RegisterFrame extends JFrame {

    private final JTextField usernameField = new JTextField(20);
    private final JPasswordField passwordField = new JPasswordField(20);

    private final AuthService authService = new AuthService();
    private final JFrame parent;

    public RegisterFrame(JFrame parent) {
        this.parent = parent;

        setTitle("SecureVault - Register");
        setDefaultCloseOperation(JFrame.DISPOSE_ON_CLOSE);
        setSize(460, 220);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(6, 6, 6, 6);
        gc.anchor = GridBagConstraints.WEST;

        gc.gridx = 0; gc.gridy = 0; panel.add(new JLabel("Username:"), gc);
        gc.gridx = 1; panel.add(usernameField, gc);

        gc.gridx = 0; gc.gridy = 1; panel.add(new JLabel("Password:"), gc);
        gc.gridx = 1; panel.add(passwordField, gc);

        JButton createBtn = new JButton("Create Account");
        JButton backBtn = new JButton("Back to Login");

        JPanel btns = new JPanel();
        btns.add(createBtn);
        btns.add(backBtn);

        gc.gridx = 0; gc.gridy = 2; gc.gridwidth = 2;
        gc.anchor = GridBagConstraints.CENTER;
        panel.add(btns, gc);

        setContentPane(panel);

        createBtn.addActionListener(e -> doRegister());
        backBtn.addActionListener(e -> {
            this.dispose();
            parent.setVisible(true);
        });
    }

    private void doRegister() {
        try {
            String username = usernameField.getText().trim();
            char[] password = passwordField.getPassword();

            User user = authService.register(username, password);

            java.util.Arrays.fill(password, '\0');

            // Build otpauth URL + generate QR PNG
            String issuer = "SecureVault";
            String otpAuthUrl = TotpUtil.buildOtpAuthUrl(username, issuer, user.getTotpSecret());
            String qrFileName = "qrcode_" + username + ".png";
            QrCodeUtil.generateQrCode(otpAuthUrl, qrFileName, 320, 320);

            // Show QR inside Swing (A)
            new QrSetupDialog(this, username, user.getTotpSecret(), qrFileName).setVisible(true);
            AuditLogger.log("REGISTER_SUCCESS", username, "User created, QR generated for SafeAuth");

        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Registration error: " + ex.getMessage());
        }
    }
}
