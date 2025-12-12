/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.ui;

import ie.ncirl.securevault.auth.AuthService;
import ie.ncirl.securevault.logging.AuditLogger;

import javax.swing.*;
import java.awt.*;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class LoginFrame extends JFrame {

    private final JTextField usernameField = new JTextField(20);
    private final JPasswordField passwordField = new JPasswordField(20);
    private final JTextField totpField = new JTextField(6);

    private final AuthService authService = new AuthService();

    public LoginFrame() {
        setTitle("SecureVault - Login");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(420, 240);
        setLocationRelativeTo(null);

        JPanel panel = new JPanel(new GridBagLayout());
        GridBagConstraints gc = new GridBagConstraints();
        gc.insets = new Insets(6, 6, 6, 6);
        gc.anchor = GridBagConstraints.WEST;

        gc.gridx = 0; gc.gridy = 0; panel.add(new JLabel("Username:"), gc);
        gc.gridx = 1; panel.add(usernameField, gc);

        gc.gridx = 0; gc.gridy = 1; panel.add(new JLabel("Password:"), gc);
        gc.gridx = 1; panel.add(passwordField, gc);

        gc.gridx = 0; gc.gridy = 2; panel.add(new JLabel("TOTP Code:"), gc);
        gc.gridx = 1; panel.add(totpField, gc);

        JButton loginBtn = new JButton("Login");
        JButton registerBtn = new JButton("Register");

        JPanel btns = new JPanel();
        btns.add(loginBtn);
        btns.add(registerBtn);

        gc.gridx = 0; gc.gridy = 3; gc.gridwidth = 2;
        gc.anchor = GridBagConstraints.CENTER;
        panel.add(btns, gc);

        setContentPane(panel);

        loginBtn.addActionListener(e -> doLogin());
        registerBtn.addActionListener(e -> {
            new RegisterFrame(this).setVisible(true);
            this.setVisible(false);
        });
    }

    private void doLogin() {
        try {
            String username = usernameField.getText().trim();
            char[] password = passwordField.getPassword();
            int code = Integer.parseInt(totpField.getText().trim());

            boolean ok = authService.verifyLogin(username, password, code);

            // Clear password in memory after use
            java.util.Arrays.fill(password, '\0');

            if (ok) {
                JOptionPane.showMessageDialog(this, "✅ Login successful!");
                // on success:
                AuditLogger.log("LOGIN_SUCCESS", username, "Password+TOTP verified");
                // Next: open dashboard
                new VaultDashboardFrame(username).setVisible(true);
                this.dispose();
            } else {
                JOptionPane.showMessageDialog(this, "❌ Login failed. Check password or TOTP.");
                // on fail:
                AuditLogger.log("LOGIN_FAIL", username, "Invalid password or TOTP");
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(this, "Login error: " + ex.getMessage());
        }
    }
}