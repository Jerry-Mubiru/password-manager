import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.util.Scanner;

public class Main {
    public static void main(String[] args) {

        Scanner scanner = new Scanner(System.in);
        promptForPasscode();
        String passcode = scanner.nextLine();
        // Check whether a password file exists or not.
        if (isFileExists()){
            //Initialize from the file.
            PasswordFileManager.initializeFromFile("passwords.txt");
            // Verify the passcode.
            handlePasscodeVerification(passcode, scanner);
        }
        else {
            // File doesn't exist. Add file. Prompt for User choice.
            try {
                addPasswordFile(passcode);
            } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new RuntimeException(e);
            }
            handlePasscodeVerification(passcode, scanner);
        }
        scanner.close();
        System.exit(0);
    }

    // Handles the user choice Recursively.
    private static void handleUserChoice(String choice, Scanner scanner) {
        // base case is the quit option.
        switch (choice) {
            case "q":
                // Save the file.
                PasswordFileManager.generateFile("passwords.txt");
                return;
            case "a": {
                // Prompt for label.
                promptForPasswordLabel();
                String label = scanner.nextLine();
                // Prompt for password.
                promptForPasswordToStore();
                String password = scanner.nextLine();
                // ADD.
                storeLabelAndPassword(label, password);
                // Prompt for new user choice.
                promptForUserChoice();
                String newUserChoice = scanner.nextLine();
                // Recursive handle of new user choice.
                handleUserChoice(newUserChoice, scanner);
                break;
            }
            case "r": {
                // Prompt for label
                promptForPasswordLabel();
                // Prompt returned password.
                String label = scanner.nextLine();
                String password = getPasswordFromLabel(label);
                promptPasswordToUser(password);
                // Prompt for user choice again.
                promptForUserChoice();
                String newUserChoice = scanner.nextLine();
                // Recursive handle of new user choice.
                handleUserChoice(newUserChoice, scanner);
                break;
            }
            default: {
                // Prompt invalid input.
                promptInvalidUserChoice();
                // Prompt for new user choice.
                promptForUserChoice();
                String newUserChoice = scanner.nextLine();
                // Recursive handle of new user choice.
                handleUserChoice(newUserChoice, scanner);
            }
        }
    }
    private static void handlePasscodeVerification(String passcode, Scanner scanner) {
        if (isCorrectPasscode(passcode)) {
            // Base case. Proceed normally.
            promptForUserChoice();
            String choice = scanner.nextLine();
            handleUserChoice(choice, scanner);
        }
        else {
            // Must try again.
            promptInvalidPasscode();
            promptForPasscode();
            String newPasscode = scanner.nextLine();
            handlePasscodeVerification(newPasscode, scanner);
        }
    }

    private static void addPasswordFile(String passcode) throws NoSuchAlgorithmException, InvalidKeySpecException {
        // Prompt user of backend events.
        promptFileAddition();
        // initialize the password file manager with given passcode.
        PasswordFileManager.initialize(passcode);
    }

    private static void promptFileAddition(){
        System.out.println("No Password file detected. Creating a new password file.");
    }

    private static void promptInvalidPasscode(){
        System.out.println("Invalid passcode! Access Denied.");
    }

    private static void promptForPasswordLabel(){
        System.out.println("Enter label for password: ");
    }
    private static void promptForPasswordToStore(){
        System.out.println("Enter password to store: ");
    }

    private static void storeLabelAndPassword(String label, String password){
        PasswordFileManager.addPassword(label,password);
    }

    private static String getPasswordFromLabel(String label){
        // File interactions and dictionary handling.
       return PasswordFileManager.getPassword(label);
    }
    private static void promptPasswordToUser(String password){
        System.out.println("Found: " + password);
    }
    private static void promptInvalidUserChoice(){
        System.out.println("Invalid user choice! Please input 'a' 'r' or 'q'.");
    }

    // Prompts the user for a passcode to access their manager.
    private static void promptForPasscode(){

        System.out.println("Enter the passcode to access your passwords: ");
    }

    // Checks whether a password file `passwords.txt` for the user exists.
    private static boolean isFileExists(){
        String path = "passwords.txt";
        try (FileInputStream fis = new FileInputStream(path)){
            return true;
        }
        catch (IOException e){
            return false;
        }
    }

    // Verifies that the passcode is correct.
    private static boolean isCorrectPasscode(String passcode){
        return PasswordFileManager.verifyPasscode(passcode);
    }

    private static void promptForUserChoice(){
        System.out.println
                ("a : Add Password\nr : Read Password\nq : Quit\nEnter choice : ");
    }
}