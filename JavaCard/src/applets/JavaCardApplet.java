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

    private static final byte MASTER_KEY_LENGTH = (byte) 32;

    private static final byte PIN_TRY_LIMIT = (byte) 5;
    private static final byte PIN_SIZE = (byte) 4;

    private byte[] masterKey;
    private OwnerPIN pin;
    private final RandomData randomData;
    // Buffer to store the derived key
    private byte[] derivedKey;
    private MessageDigest sha;

    public JavaCardApplet() {
        masterKey = new byte[MASTER_KEY_LENGTH];
        derivedKey = new byte[32];
        
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
        
        randomData = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
        pin = new OwnerPIN(PIN_TRY_LIMIT, PIN_SIZE);
        byte[] defaultPin = {0x31, 0x32, 0x33, 0x34}; // "1234"
        pin.update(defaultPin, (short) 0, PIN_SIZE);
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
    
    private void deriveKey(APDU apdu) {
        if (masterKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        byte derivationIndex = buffer[ISO7816.OFFSET_CDATA];
        sha.reset();
        sha.update(masterKey, (short) 0, (short) masterKey.length);
        sha.doFinal(new byte[]{ derivationIndex }, (short) 0, (short) 1, derivedKey, (short) 0);
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
