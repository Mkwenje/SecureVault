/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package ie.ncirl.securevault.securevault;

import ie.ncirl.securevault.auth.QrCodeUtil;
import ie.ncirl.securevault.auth.TotpUtil;

import ie.ncirl.securevault.auth.AuthService;
import ie.ncirl.securevault.db.Database;
import ie.ncirl.securevault.model.User;

import java.sql.SQLException;
import java.util.Scanner;
/**
 *
 * @author Mkwenje Tadiwa
 */
/**
 * SecureVault (temporary console front-end)
 *
 * This main class is a simple console-based interface used only for
 * development and testing:
 *  - Option 1: Register a new user.
 *  - Option 2: Login with username, password, and TOTP code.
 *
 * In the final project this will be replaced by a Swing GUI, but the logic
 * here shows clearly how the AuthService is used.
 */
public class SecureVault {

    public static void main(String[] args) throws Exception {
        // Ensure the database and tables exist.
        Database.initialize();
        System.out.println("Database initialized.");

        AuthService authService = new AuthService();
        Scanner scanner = new Scanner(System.in);

        System.out.println("1) Register  2) Login");
        System.out.print("Choose option: ");
        int choice = Integer.parseInt(scanner.nextLine().trim());

        if (choice == 1) {
            doRegister(authService, scanner);
        } else if (choice == 2) {
            doLogin(authService, scanner);
        } else {
            System.out.println("Unknown option.");
        }
    }

    /**
     * Handles the registration flow:
     *  - Ask for username and password.
     *  - Call AuthService.register.
     *  - Print the TOTP secret so the user can add it to an authenticator app.
     */
    private static void doRegister(AuthService authService, Scanner scanner) throws SQLException {
        System.out.print("Choose a username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Choose a password: ");
        String password = scanner.nextLine(); // for demo; GUI will hide this

        User user = authService.register(username, password.toCharArray());
        System.out.println("User registered with id=" + user.getId());

        // TOTP secret for this user
        String secret = user.getTotpSecret();

        // Build otpauth URL using the standard Key URI Format.
        String issuer = "SecureVault";  // name of your application
        String otpAuthUrl = TotpUtil.buildOtpAuthUrl(username, issuer, secret);

        // Generate QR code image file in the project folder.
        String qrFileName = "qrcode_" + username + ".png";
        try {
            QrCodeUtil.generateQrCode(otpAuthUrl, qrFileName, 300, 300);
            System.out.println("\nA QR code has been generated for your authenticator:");
            System.out.println("QR file: " + qrFileName);
        } catch (Exception e) {
            System.out.println("Could not generate QR code image: " + e.getMessage());
        }

        System.out.println("\n=== TOTP SETUP INSTRUCTIONS ===");
        System.out.println("1. Install or open the app:  Authenticator App - SafeAuth");
        System.out.println("2. In SafeAuth, choose 'Add account' and then 'Scan QR code'.");
        System.out.println("3. Scan the QR code image file: " + qrFileName);
        System.out.println("   (The image is in the same folder as this application).");
        System.out.println("4. If you cannot scan the QR code, use manual entry with:");
        System.out.println("   Account name: " + username);
        System.out.println("   Secret key : " + secret);
        System.out.println("   Type       : Time-based (TOTP), 6 digits, 30-second period.");
        System.out.println("5. After adding the account in SafeAuth, use the 6-digit code it displays");
        System.out.println("   during login to complete multi-factor authentication.");
        System.out.println("================================\n");
    }

    /**
     * Handles the login flow:
     *  - Ask for username, password, and the 6-digit TOTP code.
     *  - Use AuthService.verifyLogin to check credentials and MFA.
     */
    private static void doLogin(AuthService authService, Scanner scanner) throws SQLException {
        System.out.print("Username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Password: ");
        String password = scanner.nextLine();

        System.out.print("TOTP code (from your authenticator app): ");
        String codeStr = scanner.nextLine().trim();
        int code = Integer.parseInt(codeStr);

        boolean ok = authService.verifyLogin(username, password.toCharArray(), code);
        if (ok) {
            System.out.println("✅ Login successful (password + MFA correct).");
        } else {
            System.out.println("❌ Login failed (check password or TOTP).");
        }
    }
}