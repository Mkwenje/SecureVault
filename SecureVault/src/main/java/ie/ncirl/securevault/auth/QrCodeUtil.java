/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
package ie.ncirl.securevault.auth;

import com.google.zxing.BarcodeFormat;
import com.google.zxing.MultiFormatWriter;
import com.google.zxing.WriterException;
import com.google.zxing.client.j2se.MatrixToImageWriter;
import com.google.zxing.common.BitMatrix;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Path;

/**
 * QrCodeUtil
 *
 * Helper for generating QR code images from a text string.
 * This uses the open-source ZXing (Zebra Crossing) library.
 *
 * In your report you can reference ZXing as the source of the
 * QR code generation algorithm and APIs.
 * @author Mkwenje Tadiwa
 */
public class QrCodeUtil {
    
    
    /**
     * Generates a QR code PNG file for the given text.
     *
     * @param text      the data to encode (e.g. an otpauth:// URL).
     * @param filePath  where to save the PNG (e.g. "qrcode_username.png").
     * @param width     image width in pixels.
     * @param height    image height in pixels.
     */
    public static void generateQrCode(String text, String filePath, int width, int height)
            throws WriterException, IOException {

        BitMatrix matrix = new MultiFormatWriter()
                .encode(text, BarcodeFormat.QR_CODE, width, height);

        Path path = FileSystems.getDefault().getPath(filePath);
        MatrixToImageWriter.writeToPath(matrix, "PNG", path);
    }
}
