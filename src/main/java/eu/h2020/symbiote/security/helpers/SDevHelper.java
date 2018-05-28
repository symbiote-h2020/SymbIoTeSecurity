package eu.h2020.symbiote.security.helpers;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

/**
 * Utility class containing helper methods for SDEV authentication
 *
 * @author Mikołaj Dobski (PSNC)
 * @author Jakub Toczek (PSNC)
 */

public class SDevHelper {

    /**
     * Utility class to hash a string with SHA1
     *
     * @param stringToHash string that needs to be hashed
     * @return the hexadecimal hashed string
     */
    public static String hashSHA1(String stringToHash) throws
            NoSuchAlgorithmException {

        MessageDigest messageDigest = MessageDigest.getInstance("SHA-1");
        byte[] byteHash = messageDigest.digest(stringToHash.getBytes(StandardCharsets.UTF_8));
        String hexHash = new String(Hex.encode(byteHash)); // byte to hex converter to get the hashed value in hexadecimal
        messageDigest.reset();

        return hexHash;
    }
}
