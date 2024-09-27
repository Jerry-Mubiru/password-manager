import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Base64;
import java.util.Hashtable;


/*
* This class represents a File manager for the passwords.
* The class is serializable to allow its easy conversion to json.
*/
public class PasswordFileManager implements Serializable {
    // Stores the encrypted salt.
    private static String salt;
    // Stores the encrypted token.
    private static String token;
    // Stores a Dictionary for labels and associated passwords.
    private static Hashtable<String, String> passwords;
    // Data class
    static class PasswordData {
        String salt;
        String token;
        Hashtable<String, String> passwords;

        public PasswordData(String salt, String token, Hashtable<String, String> passwords) {
            this.salt = salt;
            this.token = token;
            this.passwords = passwords;
        }
    }
    public static void initialize(String passcode) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Generate a salt.
        SecureRandom random = new SecureRandom();
        byte[] saltBytes = new byte[16];
        random.nextBytes(saltBytes);

        // Store the Base 64 encoded salt.
        salt = Base64.getEncoder().encodeToString(saltBytes);
        // Hash the passcode and the salt to create a key.
        token = hashPasscode(passcode);
        passwords = new Hashtable<>();
        // Generate the file.
        generateFile("passwords.txt");
    }

    public static void generateFile(String filepath) {
        PasswordData data = new PasswordData(salt, token, passwords);
        saveToFile(data, filepath);
    }

    private static void saveToFile(PasswordData data, String filePath) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(filePath))) {
            // Write the salt and token
            writer.write("Salt: " + data.salt);
            writer.newLine();
            writer.write("Token: " + data.token);
            writer.newLine();

            if (data.passwords != null) {
                // Write passwords from Hashtable
                for (String label : data.passwords.keySet()) {
                    writer.write(label + ": " + data.passwords.get(label));
                    writer.newLine();
                }
            }
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Method to initialize PasswordData from a file
    public static void initializeFromFile(String filePath) {
        Hashtable<String, String> passwordMap = new Hashtable<>();
        String saltLocal = null;
        String tokenLocal = null;

        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                // Check for salt and token
                if (line.startsWith("Salt: ")) {
                    saltLocal = line.substring(6);
                } else if (line.startsWith("Token: ")) {
                    tokenLocal = line.substring(7);
                } else {
                    // Split label and password
                    String[] parts = line.split(": ", 2);
                    if (parts.length == 2) {
                        passwordMap.put(parts[0], parts[1]);
                    }
                }
            }
            PasswordData data =  new PasswordData(saltLocal, tokenLocal, passwordMap);
            salt = data.salt;
            token = data.token;
            passwords = data.passwords;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    // Encrypting and encode.
    public static boolean verifyPasscode(String userPasscode) {
        // Get the salt and combine it with the passcode.
        String userHash = hashPasscode(userPasscode);
        // Compare it with the stored token.
        return userHash.equals(token);
    }

    private static String hashPasscode(String passcode) {
        try {
                // Decode the salt to a byte array.
                byte[] decodedSalt = Base64.getDecoder().decode(salt);
                // Hash the passcode and salt to create a key.
                KeySpec spec = new PBEKeySpec(passcode.toCharArray(), decodedSalt, 600000, 128);
                SecretKeyFactory keyFactory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
                SecretKey userKey = keyFactory.generateSecret(spec);
                byte[] encoded = userKey.getEncoded();
                return Base64.getEncoder().encodeToString(encoded);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            return "";
        }
    }

    public static void addPassword(String label, String password) {
        // Encrypt the password.
        String result;
        try {
            passwords.put(label,encrypt(password, getKey(token)));
        } catch (NoSuchPaddingException | BadPaddingException | IllegalBlockSizeException | InvalidKeyException |
                 NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public static String getPassword(String label) {
        // Return the value from the label key.
        String encryptedPassword = passwords.get(label);
        // Decrypt the password.
        String returnedPassword = "";
        try {
            returnedPassword = decrypt(encryptedPassword, getKey(token));
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException |
                                                                BadPaddingException | IllegalBlockSizeException |
                                                                InvalidKeyException e) {
            throw new RuntimeException(e);
        }
        return returnedPassword;
    }

    private static SecretKey getKey(String token) {
        byte[] keyBytes = Base64.getDecoder().decode(token);
        return new SecretKeySpec(keyBytes, "AES");
    }
    private static String encrypt(String password, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.ENCRYPT_MODE, key);
        byte[] encryptedPassword = cipher.doFinal(password.getBytes());
        return Base64.getEncoder().encodeToString(encryptedPassword);
    }
    private static String decrypt(String encryptedPassword, SecretKey key) throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
        Cipher cipher = Cipher.getInstance("AES");
        cipher.init(Cipher.DECRYPT_MODE, key);
        byte[] decodedEncryptedPassword = Base64.getDecoder().decode(encryptedPassword);
        byte[] decryptedPassword = cipher.doFinal(decodedEncryptedPassword);
        return new String(decryptedPassword);
    }
}
