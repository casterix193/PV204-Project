package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

import static javacard.framework.ISO7816.OFFSET_P1;

public class JavaCardApplet extends Applet implements MultiSelectable {

    private static final byte INS_DERIVE_KEY = (byte) 0x55;
    private static final byte INS_GENERATE_MASTER_KEY = (byte) 0x56;
    private static final byte INS_LOAD_MASTER_KEY = (byte) 0x57;

    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;

    private static final byte MAX_DERIVATION_PATH_LENGTH = (byte) 16;
    private static final byte MASTER_KEY_LENGTH = (byte) 32;

    private static final byte PIN_TRY_LIMIT = (byte) 5;
    private static final byte PIN_SIZE = (byte) 4;

    private byte[] masterKey;
    private OwnerPIN pin;
    private final RandomData randomData;
    // Buffer to store the derived key
    private byte[] derivedKey;
    private MessageDigest sha;

    static final short CHAIN_CODE_SIZE = 32;

    static final byte TLV_KEY_TEMPLATE = (byte) 0xA1;
    static final byte TLV_PUB_KEY = (byte) 0x80;
    static final byte TLV_CHAIN_CODE = (byte) 0x82;

    private Crypto crypto;
    private SECP256k1 secp256k1;

    private byte[] derivationOutput;

    public JavaCardApplet() {
        masterKey = new byte[MASTER_KEY_LENGTH];
        derivedKey = new byte[32];
        Crypto crypto = new Crypto();
        SECP256k1 secp256k1 = new SECP256k1();
        derivationOutput = JCSystem.makeTransientByteArray((short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE), JCSystem.CLEAR_ON_RESET);
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
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateMasterKey() {
        randomData.generateData(masterKey, (short) 0, (short) masterKey.length);
    }

    private void exportKey(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        short dataLen = secureChannel.preprocessAPDU(apduBuffer);

        if (!pin.isValidated() || !masterPrivate.isInitialized()) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        updateDerivationPath(apduBuffer, (short) 0, dataLen, derivationSource);

        doDerive(apduBuffer, (short) 0);

        short off = SecureChannel.SC_OUT_OFFSET;

        apduBuffer[off++] = TLV_KEY_TEMPLATE;
        off++;

        short len;

        apduBuffer[off++] = TLV_PUB_KEY;
        off++;
        len = secp256k1.derivePublicKey(derivationOutput, (short) 0, apduBuffer, off);
        apduBuffer[(short) (off - 1)] = (byte) len;
        off += len;

        apduBuffer[off++] = TLV_CHAIN_CODE;
        off++;
        Util.arrayCopyNonAtomic(derivationOutput, Crypto.KEY_SECRET_SIZE, apduBuffer, off, CHAIN_CODE_SIZE);
        len = CHAIN_CODE_SIZE;
        apduBuffer[(short) (off - 1)] = (byte) len;
        off += len;

        len = (short) (off - SecureChannel.SC_OUT_OFFSET);
        apduBuffer[(SecureChannel.SC_OUT_OFFSET + 1)] = (byte) (len - 2);

        if (makeCurrent) {
            commitTmpPath();
        }

        secureChannel.respond(apdu, len, ISO7816.SW_NO_ERROR);
    }


    private void sign(APDU apdu) {
        byte[] apduBuffer = apdu.getBuffer();
        boolean usePinless = false;
        boolean makeCurrent = false;
        byte derivationSource = (byte) (apduBuffer[OFFSET_P1] & DERIVE_P1_SOURCE_MASK);

        switch((byte) (apduBuffer[OFFSET_P1] & ~DERIVE_P1_SOURCE_MASK)) {
            case SIGN_P1_CURRENT_KEY:
                derivationSource = DERIVE_P1_SOURCE_CURRENT;
                break;
            case SIGN_P1_DERIVE:
                break;
            case SIGN_P1_DERIVE_AND_MAKE_CURRENT:
                makeCurrent = true;
                break;
            case SIGN_P1_PINLESS:
                usePinless = true;
                derivationSource = DERIVE_P1_SOURCE_PINLESS;
                break;
            default:
                ISOException.throwIt(ISO7816.SW_WRONG_P1P2);
                return;
        }

        short len;

        if (usePinless && !secureChannel.isOpen()) {
            len = (short) (apduBuffer[ISO7816.OFFSET_LC] & (short) 0xff);
        } else {
            len = secureChannel.preprocessAPDU(apduBuffer);
        }

        if (usePinless && pinlessPathLen == 0) {
            ISOException.throwIt(SW_REFERENCED_DATA_NOT_FOUND);
        }

        if (len < MessageDigest.LENGTH_SHA_256) {
            ISOException.throwIt(ISO7816.SW_WRONG_DATA);
        }

        short pathLen = (short) (len - MessageDigest.LENGTH_SHA_256);
        updateDerivationPath(apduBuffer, MessageDigest.LENGTH_SHA_256, pathLen, derivationSource);

        if (!((pin.isValidated() || usePinless || isPinless()) && masterPrivate.isInitialized())) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        doDerive(apduBuffer, MessageDigest.LENGTH_SHA_256);

        apduBuffer[SecureChannel.SC_OUT_OFFSET] = TLV_SIGNATURE_TEMPLATE;
        apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 3)] = TLV_PUB_KEY;
        short outLen = apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 4)] = Crypto.KEY_PUB_SIZE;

        secp256k1.derivePublicKey(derivationOutput, (short) 0, apduBuffer, (short) (SecureChannel.SC_OUT_OFFSET + 5));

        outLen += 5;
        short sigOff = (short) (SecureChannel.SC_OUT_OFFSET + outLen);

        signature.init(secp256k1.tmpECPrivateKey, Signature.MODE_SIGN);

        outLen += signature.signPreComputedHash(apduBuffer, ISO7816.OFFSET_CDATA, MessageDigest.LENGTH_SHA_256, apduBuffer, sigOff);
        outLen += crypto.fixS(apduBuffer, sigOff);

        apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 1)] = (byte) 0x81;
        apduBuffer[(short)(SecureChannel.SC_OUT_OFFSET + 2)] = (byte) (outLen - 3);

        if (makeCurrent) {
            commitTmpPath();
        }

        if (secureChannel.isOpen()) {
            secureChannel.respond(apdu, outLen, ISO7816.SW_NO_ERROR);
        } else {
            apdu.setOutgoingAndSend(SecureChannel.SC_OUT_OFFSET, outLen);
        }
    }


    /**
     * Internal derivation function, called by DERIVE KEY and EXPORT KEY
     * @param apduBuffer the APDU buffer
     * @param off the offset in the APDU buffer relative to the data field
     */
    private void doDerive(byte[] apduBuffer, short off) {
        if (tmpPathLen == 0) {
            masterPrivate.getS(derivationOutput, (short) 0);
            return;
        }

        short scratchOff = (short) (ISO7816.OFFSET_CDATA + off);
        short dataOff = (short) (scratchOff + Crypto.KEY_DERIVATION_SCRATCH_SIZE);

        short pubKeyOff = (short) (dataOff + masterPrivate.getS(apduBuffer, dataOff));
        pubKeyOff = Util.arrayCopyNonAtomic(chainCode, (short) 0, apduBuffer, pubKeyOff, CHAIN_CODE_SIZE);

        if (!crypto.bip32IsHardened(tmpPath, (short) 0)) {
            masterPublic.getW(apduBuffer, pubKeyOff);
        } else {
            apduBuffer[pubKeyOff] = 0;
        }

        for (short i = 0; i < tmpPathLen; i += 4) {
            if (i > 0) {
                Util.arrayCopyNonAtomic(derivationOutput, (short) 0, apduBuffer, dataOff, (short) (Crypto.KEY_SECRET_SIZE + CHAIN_CODE_SIZE));

                if (!crypto.bip32IsHardened(tmpPath, i)) {
                    secp256k1.derivePublicKey(apduBuffer, dataOff, apduBuffer, pubKeyOff);
                } else {
                    apduBuffer[pubKeyOff] = 0;
                }
            }

            if (!crypto.bip32CKDPriv(tmpPath, i, apduBuffer, scratchOff, apduBuffer, dataOff, derivationOutput, (short) 0)) {
                ISOException.throwIt(ISO7816.SW_DATA_INVALID);
            }
        }
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
