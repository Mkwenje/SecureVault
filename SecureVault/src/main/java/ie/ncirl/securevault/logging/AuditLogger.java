/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.logging;

import java.io.IOException;
import java.nio.file.*;
import java.time.Instant;

/**
 *
 * @author Mkwenje Tadiwa
 */
public class AuditLogger {
    
    
    private static final Path LOG_PATH = Paths.get("audit.log");

    public static void log(String event, String username, String details) {
        String line = Instant.now() + " | " + event + " | user=" + username + " | " + details + System.lineSeparator();
        try {
            Files.writeString(
                    LOG_PATH,
                    line,
                    StandardOpenOption.CREATE,
                    StandardOpenOption.WRITE,
                    StandardOpenOption.APPEND
            );
        } catch (IOException e) {
            // Don't crash the app because logging failed
            System.out.println("Audit log failed: " + e.getMessage());
        }
    }
}
