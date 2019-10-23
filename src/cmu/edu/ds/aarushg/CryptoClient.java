/***
 * authorID: aarushg
 * authorName: Aarush Gupta
 * This program implements a TCP client and the RSA algorithm is used to generate client ID and signature of the
 * client. It shows a menu to the user in order to perform computation once the client ID and signature have been
 * verified.
 */

package cmu.edu.ds.aarushg;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.net.Socket;
import java.net.SocketException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Random;
import java.util.Scanner;

public class CryptoClient {

    /***
     * n - modulus for both the private and public keys
     * e - exponent of the public key
     * d - exponent of the private key
     */

    static BigInteger n;
    static BigInteger e;
    static BigInteger d;

    /***
     * main() method
     *
     * @param args
     */

    public static void main(String[] args) {

        /***
         * Generate two large prime numbers with a 400 bit length. Compute n by p*q. Compute phi(n) = (p-1) * (q-1).
         * Select a small odd integer e that is relatively prime to phi(n) - 65537. Compute d as the multiplicative
         * inverse of e modulo phi(n). Concatenate e and n after converting the BigInteger to a string. Hash to
         * generate clientID.
         */

        Random rnd = new Random();
        BigInteger p = new BigInteger(400, 100, rnd);
        BigInteger q = new BigInteger(400, 100, rnd);
        n = p.multiply(q);
        BigInteger phi = (p.subtract(BigInteger.ONE)).multiply(q.subtract(BigInteger.ONE));
        e = new BigInteger("65537");
        d = e.modInverse(phi);
        String eBigIntegerString = String.valueOf(e);
        String nBigIntegerString = String.valueOf(n);
        String newBigIntegerString = eBigIntegerString + nBigIntegerString;
        String hash = ComputeSHA_256_as_Hex_String(newBigIntegerString);
        String clientID = hash.substring(hash.length() - 40);
        String operationValue = "1";
        String userInputValue = null;
        Scanner scanner = new Scanner(System.in);

        /***
         * Sends a TCP request. Initializes socket, input and output streams. Starts the server and waits for
         * a connection. Display a menu for the user to add, subtract, view the data or quit the program.
         */

        Socket clientSocket = null;
        try {
            System.out.println("---Client running---");
            int serverPort = 7777;
            clientSocket = new Socket("localhost", serverPort);
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(new BufferedWriter(new OutputStreamWriter(clientSocket.getOutputStream())));
            System.out.println("ClientID: " + clientID);
            while (true) {
                System.out.print("\n1. Add \n2. Subtract \n3. View \n4. Quit \nEnter Operation to be performed: ");
                operationValue = scanner.nextLine();
                if (operationValue.equals("4")) {
                    System.out.println("Client is closing");
                    out.close();
                    break;
                } else if (operationValue.equals("3")) {
                    userInputValue = "-1";
                } else {
                    System.out.println("Enter Value");
                    userInputValue = scanner.nextLine();
                }

                /***
                 * key -> client id + public key (e+n) + user input operation + user input value
                 * signature -> stores the encrypted key
                 * requestString -> concatenated string to be sent to the server separated by commas
                 * Send requestString to the server
                 * data -> Read data from the server
                 * Handling general exceptions
                 */

                String key;
                String signature = null;
                key = clientID + newBigIntegerString + operationValue + userInputValue;
                String hashedKey = ComputeSHA_256_as_Hex_String(key);
                try {
                    signature = sign(hashedKey);
                } catch (Exception e) {
                    System.out.println("Exception e");
                }
                String requestString = clientID + "," + operationValue + "," + userInputValue + "," + signature + "," + e.toString() + "," + n.toString();
                out.println(requestString);
                out.flush();
                String data = in.readLine();
                System.out.println(data);
            }

            /***
             * Handling socket, number format and I/O exceptions.
             */

        } catch (SocketException e) {
            System.out.println("Socket: " + e.getMessage());
        } catch (NumberFormatException n) {
            System.out.println("Number format exception");
        } catch (IOException e) {
            System.out.println("IO Exception:" + e.getMessage());
        } finally {
            try {
                if (clientSocket != null) {
                    clientSocket.close();
                }
            } catch (IOException e) {
            }
        }
    }

    /***
     * sign() method
     * Convert to byte array. Create a new array to store 0 and add 0 as the most significant bit to make it
     * positive. Convert the same to a BigInteger and encrypt it with the private key.
     * @param message
     */

    public static String sign(String message) throws Exception {
        byte[] hexToByteArray = hexStringToByteArray(message);
        byte tempArray[] = new byte[hexToByteArray.length + 1];
        tempArray[0] = 0;
        for (int i = 0; i < hexToByteArray.length; i++) {
            tempArray[i + 1] = hexToByteArray[i];
        }
        BigInteger m = new BigInteger(tempArray);
        BigInteger c = m.modPow(d, n);
        return c.toString();
    }

    /***
     * ComputeSHA_256_as_Hex_String() method
     * Source: 'BabyHash' class
     * Create a SHA256 digest. Initialize byte array for storing the hash. Perform the hash and store
     * the result. Handling exceptions.
     * @param text
     */

    public static String ComputeSHA_256_as_Hex_String(String text) {
        try {
            MessageDigest digest;
            digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes;
            digest.update(text.getBytes("UTF-8"), 0, text.length());
            hashBytes = digest.digest();
            return convertToHex(hashBytes);
        } catch (NoSuchAlgorithmException nsa) {
            System.out.println("No such algorithm exception thrown " + nsa);
        } catch (UnsupportedEncodingException uee) {
            System.out.println("Unsupported encoding exception thrown " + uee);
        }
        return null;
    }

    /***
     * convertToHex() method
     * Source: StackOverflow + 'BabyHash' program
     * Converts a byte array to a String. Each nibble (4 bits) of the byte array is represented by a hex character.
     * @param data
     */

    private static String convertToHex(byte[] data) {
        StringBuffer buf = new StringBuffer();
        for (int i = 0; i < data.length; i++) {
            int halfbyte = (data[i] >>> 4) & 0x0F;
            int two_halfs = 0;
            do {
                if ((0 <= halfbyte) && (halfbyte <= 9)) {
                    buf.append((char) ('0' + halfbyte));
                } else {
                    buf.append((char) ('a' + (halfbyte - 10)));
                }
                halfbyte = data[i] & 0x0F;
            } while (two_halfs++ < 1);
        }
        return buf.toString();
    }

    /***
     * hexStringToByteArray() method
     * Source: StackOverflow + 'BabySign'
     * @param s
     */

    public static byte[] hexStringToByteArray(String s) {
        int len = s.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
                    + Character.digit(s.charAt(i + 1), 16));
        }
        return data;
    }
}