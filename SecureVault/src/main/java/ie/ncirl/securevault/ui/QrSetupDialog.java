/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.ui;

import javax.swing.*;
import java.awt.*;
import java.io.File;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class QrSetupDialog extends JDialog {

    public QrSetupDialog(JFrame owner, String username, String secret, String qrFilePath) {
        super(owner, "MFA Setup - SafeAuth", true);
        setSize(520, 520);
        setLocationRelativeTo(owner);

        JLabel title = new JLabel("Scan with: Authenticator App - SafeAuth", SwingConstants.CENTER);
        title.setFont(title.getFont().deriveFont(Font.BOLD, 16f));

        JLabel imgLabel = new JLabel("", SwingConstants.CENTER);
        ImageIcon icon = new ImageIcon(qrFilePath);
        imgLabel.setIcon(icon);

        JTextArea instructions = new JTextArea(
                "1) Open Authenticator App - SafeAuth\n" +
                "2) Add account → Scan QR code\n" +
                "3) Scan the QR code shown above\n\n" +
                "If you cannot scan, use manual entry:\n" +
                "Account: " + username + "\n" +
                "Secret:  " + secret + "\n" +
                "Type: Time-based (TOTP), 6 digits, 30s"
        );
        instructions.setEditable(false);
        instructions.setLineWrap(true);
        instructions.setWrapStyleWord(true);

        JButton ok = new JButton("Done");
        ok.addActionListener(e -> dispose());

        JPanel bottom = new JPanel(new BorderLayout());
        bottom.add(new JScrollPane(instructions), BorderLayout.CENTER);
        bottom.add(ok, BorderLayout.SOUTH);

        setLayout(new BorderLayout(10, 10));
        add(title, BorderLayout.NORTH);
        add(imgLabel, BorderLayout.CENTER);
        add(bottom, BorderLayout.SOUTH);

        // Small check for missing file
        if (!new File(qrFilePath).exists()) {
            JOptionPane.showMessageDialog(owner, "QR file not found: " + qrFilePath);
        }
    }
}