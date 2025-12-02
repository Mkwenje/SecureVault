/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 */

package ie.ncirl.securevault.securevault;

import ie.ncirl.securevault.auth.AuthService;
import ie.ncirl.securevault.db.Database;
import ie.ncirl.securevault.model.User;

import java.sql.SQLException;
import java.util.Scanner;
/**
 *
 * @author Mkwenje Tadiwa
 */
public class SecureVault {

 public static void main(String[] args) throws Exception {
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

    private static void doRegister(AuthService authService, Scanner scanner) throws SQLException {
        System.out.print("Choose a username: ");
        String username = scanner.nextLine().trim();

        System.out.print("Choose a password: ");
        String password = scanner.nextLine(); // for a real app you'd hide this input

        User user = authService.register(username, password.toCharArray());
        System.out.println("User registered with id=" + user.getId());
        System.out.println("Your TOTP secret (add to Google Authenticator):");
        System.out.println(user.getTotpSecret());
        System.out.println("Use an app like Google Authenticator, add a new account with this secret.");
    }

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
