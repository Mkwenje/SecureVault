/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.ui;

import ie.ncirl.securevault.db.Database;

import javax.swing.*;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class App {
        public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                Database.initialize();
                new LoginFrame().setVisible(true);
            } catch (Exception e) {
                JOptionPane.showMessageDialog(null, "Startup error: " + e.getMessage());
            }
        });
    }
}
