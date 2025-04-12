package host;

import applets.KeycardApplet;
import cardtools.RunConfig;
import javacard.framework.ISO7816;
import cardtools.CardManager;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.Arrays;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class TestSignCommand {

    // Replace with your applet's AID bytes.
    private static final byte[] APPLET_AID_BYTES = {
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C,
            (byte) 0x06
    };
    private static final byte CLA_BYTE = (byte) 0xB0;
    private static final byte INS_SIGN = (byte) 0xC0;
    private static final byte INS_INIT = (byte) 0xFE;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_GENERATE_KEY = (byte) 0xD4;


    private static final byte P1 = (byte) 0x00;
    private static final byte P2 = (byte) 0x00;

    private static final short EXPECTED_SIGNATURE_LENGTH = 64;
    
    // Default PIN for testing
    private static final byte[] DEFAULT_PIN = {0x31, 0x32, 0x33, 0x34, 0x35, 0x36};
    private static final byte[] initData = {
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36, // PIN
            0x31, 0x32, 0x33, 0x34, 0x35, 0x36 , 0x37, 0x38, 0x39, 0x31, 0x32, 0x33 // PUK
    };

    public static void main(String[] args) throws Exception {
        CardManager cardManager = new CardManager(true, APPLET_AID_BYTES);

        RunConfig runConfig = RunConfig.getDefaultConfig();
        runConfig.setAppletToSimulate(KeycardApplet.class);
        runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);

        System.out.print("Connecting to card simulator...");
        if (!cardManager.Connect(runConfig)) {
            throw new Exception("Connection failed.");
        }
        System.out.println("Connected.");
        initKeycard(cardManager);
        // Step 1: Verify PIN
        verifyPin(cardManager);

        // Step 2: Generate a key if needed
        generateKey(cardManager);
        
        // Step 3: Create test message (32 bytes)
        byte[] message = new byte[32];
        Arrays.fill(message, (byte) 0x01);
        
        // Step 4: Hash the message (optional if the message is already a hash)
        byte[] messageHash = hashMessage(message);
        
        // Step 5: Sign the message
        byte[] signature = signMessage(cardManager, messageHash);

        System.out.println("Test completed successfully!");
    }

    private static void initKeycard(CardManager cardManager) throws Exception {
        System.out.print("Initializing Keycard... ");
        // send 6 digits of PIN and 12 digits of PUK
        CommandAPDU initApdu = new CommandAPDU(CLA_BYTE, INS_INIT, P1, P2, initData);
        ResponseAPDU response = cardManager.transmit(initApdu);

        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            throw new Exception("Keycard initialization failed");
        }
        System.out.println("Success.");
    }

    private static void verifyPin(CardManager cardManager) throws Exception {
        System.out.print("Verifying PIN... ");
        CommandAPDU verifyPinApdu = new CommandAPDU(CLA_BYTE, INS_VERIFY_PIN, P1, P2, DEFAULT_PIN);
        ResponseAPDU response = cardManager.transmit(verifyPinApdu);
        
        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            throw new Exception("PIN verification failed");
        }
        System.out.println("Success.");
    }
    
    private static void generateKey(CardManager cardManager) throws Exception {
        System.out.print("Generating master key... ");
        CommandAPDU generateKeyCmd = new CommandAPDU(CLA_BYTE, INS_GENERATE_KEY, P1, P2);
        ResponseAPDU response = cardManager.transmit(generateKeyCmd);
        
        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            throw new Exception("Key generation failed");
        }
        System.out.println("Success.");
    }
    
    private static byte[] hashMessage(byte[] message) throws NoSuchAlgorithmException {
        // For this example, we'll just return the message if it's already 32 bytes
        if (message.length == 32) {
            return message;
        }
        
        // Otherwise, hash it with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        return digest.digest(message);
    }
    
    private static byte[] signMessage(CardManager cardManager, byte[] messageHash) throws Exception {
        System.out.print("Signing message... ");
        CommandAPDU signCmd = new CommandAPDU(CLA_BYTE, INS_SIGN, P1, P2, messageHash);
        ResponseAPDU response = cardManager.transmit(signCmd);
        
        if (response.getSW() != 0x9000) {
            System.out.println("Failed. Status word: " + Integer.toHexString(response.getSW()));
            throw new Exception("Signing failed");
        }
        
        byte[] signature = response.getData();
        System.out.println("Success. Signature received: " + signature.length + " bytes");
        return signature;
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X", b));
        }
        return sb.toString();
    }
}