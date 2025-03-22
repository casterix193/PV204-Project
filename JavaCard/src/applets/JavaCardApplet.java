package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class JavaCardApplet extends Applet implements MultiSelectable {

    private static final byte INS_DERIVE_KEY = (byte) 0x55;
    private static final byte INS_GENERATE_MASTER_KEY = (byte) 0x56;
    private static final byte INS_LOAD_MASTER_KEY = (byte) 0x57;

    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;

    private static final byte MAX_DERIVATION_PATH_LENGTH = (byte) 10;
    private static final byte MASTER_KEY_LENGTH = (byte) 32;

    private static final byte PIN_TRY_LIMIT = (byte) 5;
    private static final byte PIN_SIZE = (byte) 4;

    private byte[] masterKey;
    private OwnerPIN pin;
    private final RandomData randomData;
    // Buffer to store the derived key
    private byte[] derivedKey;
    private MessageDigest sha;

    private AESKey aesKey;
    private Cipher aesCipher;
    private byte[] aesKeyData = {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
        (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10
    };


    public JavaCardApplet() {
        masterKey = new byte[MASTER_KEY_LENGTH];
        derivedKey = new byte[32];
        
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        byte[] defaultPin = {0x31, 0x32, 0x33, 0x34}; // "1234"
        pin.update(defaultPin, (short) 0, PIN_SIZE);
        
        aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_128, false);
        aesKey.setKey(aesKeyData, (short) 0);
        aesCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_ECB_NOPAD, false);

        register();
    }

    public static void install(byte[] bArray, short bOffset, byte bLength) {
        new JavaCardApplet();
    }

    public void process(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        if (selectingApplet()) {
            return;
        }
        byte ins = buffer[ISO7816.OFFSET_INS];
        switch (ins) {
            case INS_VERIFY_PIN:
                verifyPIN(apdu);
                break;
            case INS_CHANGE_PIN:
                checkPinValidated();
                changePIN(apdu);
                break;
            case INS_DERIVE_KEY:
                checkPinValidated();
                deriveKey(apdu);
                break;
            case INS_GENERATE_MASTER_KEY:
                checkPinValidated();
                generateMasterKey();
                sendSuccessResponse(apdu);
                break;
            case INS_LOAD_MASTER_KEY:
                checkPinValidated();
                loadMasterKey(apdu);
                sendSuccessResponse(apdu);
                break;
            case (byte) 0xA1: 
                checkPinValidated();
                decryptSecureMessage(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateMasterKey() {
        randomData.generateData(masterKey, (short) 0, (short) masterKey.length);
    }

    private void loadMasterKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Get the number of bytes in the data field
        short bytesRead = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();

        if (lc != MASTER_KEY_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if we received all bytes
        if (bytesRead != lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Copy key data from buffer to masterKey
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, masterKey, (short) 0, MASTER_KEY_LENGTH);
    }


    /**
     * Derive a key from the master key using a derivation path
     * Algorithm:
     *  Start with master key
     *  For each index in path:
     *      Take current key + index
     *      Hash them together with SHA
     *      Use result as new key for next level
     */
    private void deriveKey(APDU apdu) {
        if (masterKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        // Check that we have at least one index
        if (bytesRead < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Limit path length for security
        if (bytesRead > MAX_DERIVATION_PATH_LENGTH) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Start with the master key
        Util.arrayCopyNonAtomic(masterKey, (short) 0, derivedKey, (short) 0, (short) masterKey.length);

        // For each level in the path, derive a new key
        for (short i = 0; i < bytesRead; i++) {
            byte pathIndex = buffer[(short)(ISO7816.OFFSET_CDATA + i)];

            // Use current derivedKey + pathIndex to generate next level
            sha.reset();
            sha.update(derivedKey, (short) 0, (short) derivedKey.length);
            sha.doFinal(new byte[]{ pathIndex }, (short) 0, (short) 1, derivedKey, (short) 0);
        }

        // Send derived key as response
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) derivedKey.length);
        apdu.sendBytesLong(derivedKey, (short) 0, (short) derivedKey.length);
    }

    private void verifyPIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        short bytesRead = apdu.setIncomingAndReceive();

        if (bytesRead != PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Returns 0x63CX where X is the number of tries remaining
        if (!pin.check(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE)) {
            short remainingTries = pin.getTriesRemaining();
            ISOException.throwIt((short)(0x63C0 | remainingTries));
        }

        sendSuccessResponse(apdu);
    }

    /**
     * Change the PIN (requires the current PIN to be validated)
     */
    private void changePIN(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        if (bytesRead != PIN_SIZE) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        pin.update(buffer, ISO7816.OFFSET_CDATA, PIN_SIZE);
        sendSuccessResponse(apdu);
    }

    private void decryptSecureMessage(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        // Decrypt data
        aesCipher.init(aesKey, Cipher.MODE_DECRYPT);
        aesCipher.doFinal(buffer, ISO7816.OFFSET_CDATA, bytesRead, buffer, (short) 0);

        apdu.setOutgoingAndSend((short) 0, bytesRead);
    }


    public boolean select(boolean appInstAlreadyActive) {
        return true;
    }

    public void deselect(boolean appInstAlreadyActive) {
        pin.reset();
    }
    
    public void deselect() {
        pin.reset();
    }

    private void checkPinValidated() {
        if (!pin.isValidated()) {
            ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);
        }
    }

    private void sendSuccessResponse(APDU apdu) {
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) 0);
        apdu.sendBytes((short) 0, (short) 0);
    }
}
