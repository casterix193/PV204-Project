package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class JavaCardApplet extends Applet implements MultiSelectable {

    private static final byte INS_DERIVE_KEY = (byte) 0x55;
    private static final byte INS_GENERATE_MASTER_KEY = (byte) 0x56;
    private static final byte INS_LOAD_MASTER_KEY = (byte) 0x57;
    private static final byte INS_SIGN_DATA = (byte) 0x59;

    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;

    private static final byte MASTER_KEY_LENGTH = (byte) 32;
    private final short CHAIN_CODE_LENGTH = 32;

    private static final byte PIN_TRY_LIMIT = (byte) 5;
    private static final byte PIN_SIZE = (byte) 4;

    private byte[] masterKey;
    private byte[] chainCode;
    private byte[] derivedKey;
    private byte[] tempBuffer;

    private OwnerPIN pin;
    private final RandomData randomData;
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
        chainCode = new byte[CHAIN_CODE_LENGTH];
        tempBuffer = new byte[MASTER_KEY_LENGTH + CHAIN_CODE_LENGTH];
        derivedKey = new byte[MASTER_KEY_LENGTH];
        
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA_512, false);
        
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
            case INS_SIGN_DATA:
                checkPinValidated();
                signData(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void generateMasterKey() {
        // Generate a secure random seed (32 bytes)
        byte[] seed = new byte[32];
        randomData.generateData(seed, (short) 0, (short) seed.length);

        // Use SHA-512 to derive both key and chain code from the seed
        byte[] derivationResult = new byte[64];
        sha.reset();
        sha.doFinal(seed, (short) 0, (short) seed.length, derivationResult, (short) 0);

        // First 32 bytes become the master private key
        if (masterKey == null) {
            masterKey = new byte[MASTER_KEY_LENGTH];
        }
        Util.arrayCopyNonAtomic(derivationResult, (short) 0, masterKey, (short) 0, MASTER_KEY_LENGTH);

        // Last 32 bytes become the chain code
        if (chainCode == null) {
            chainCode = new byte[CHAIN_CODE_LENGTH];
        }
        Util.arrayCopyNonAtomic(derivationResult, MASTER_KEY_LENGTH, chainCode, (short) 0, CHAIN_CODE_LENGTH);

        // Clear the temporary arrays for security
        Util.arrayFillNonAtomic(derivationResult, (short) 0, (short) derivationResult.length, (byte) 0);
        Util.arrayFillNonAtomic(seed, (short) 0, (short) seed.length, (byte) 0);
    }

    private void signData(APDU apdu) {
        if (masterKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();
        short dataOffset = ISO7816.OFFSET_CDATA;

        // Ensure we have at least 1 byte for path length
        if (bytesRead < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Read path length
        byte pathLength = buffer[dataOffset++];

        // Validate path fits in the APDU
        if (dataOffset + pathLength > bytesRead) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] currentPrivateKey = new byte[32];
        byte[] currentChainCode = new byte[32];

        // Derive private key only if path has elements
        if (pathLength > 0) {
            derivePrivateKey(buffer, dataOffset, pathLength, currentPrivateKey, currentChainCode);
        } else {
            // Use master key directly
            Util.arrayCopyNonAtomic(masterKey, (short) 0, currentPrivateKey, (short) 0, (short) 32);
            Util.arrayCopyNonAtomic(chainCode, (short) 0, currentChainCode, (short) 0, (short) 32);
        }

        // Skip past the path
        dataOffset += pathLength;

        // Data to sign starts immediately after path
        // Data length = total bytes received - bytes used for path info
        short dataLength = (short)(bytesRead - dataOffset);

        // Make sure we have some data to sign
        if (dataLength <= 0) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Generate EC key pair from derived private key
        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();

        // Set curve parameters and private key
        Secp256k1.setCommonCurveParameters(privateKey);
        privateKey.setS(currentPrivateKey, (short) 0, (short) 32);

        // Sign the data
        Signature signature = Signature.getInstance(Signature.ALG_ECDSA_SHA, false);
        signature.init(privateKey, Signature.MODE_SIGN);

        byte[] signatureBuffer = new byte[72]; // ECDSA signatures are ~70-72 bytes
        short sigLength = signature.sign(buffer, dataOffset, dataLength, signatureBuffer, (short) 0);

        // Return signature
        apdu.setOutgoing();
        apdu.setOutgoingLength(sigLength);
        apdu.sendBytesLong(signatureBuffer, (short) 0, sigLength);
    }

    private void loadMasterKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();

        // Get the number of bytes in the data field
        short bytesRead = apdu.setIncomingAndReceive();
        short lc = apdu.getIncomingLength();

        // We now expect 64 bytes: 32 for master key + 32 for chain code
        if (lc != (short)(MASTER_KEY_LENGTH + CHAIN_CODE_LENGTH)) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Check if we received all bytes
        if (bytesRead != lc) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        // Initialize if needed
        if (masterKey == null) {
            masterKey = new byte[MASTER_KEY_LENGTH];
            chainCode = new byte[CHAIN_CODE_LENGTH];
        }

        // Copy first 32 bytes as master key
        Util.arrayCopy(buffer, ISO7816.OFFSET_CDATA, masterKey, (short) 0, MASTER_KEY_LENGTH);

        // Copy last 32 bytes as chain code
        Util.arrayCopy(buffer, (short)(ISO7816.OFFSET_CDATA + MASTER_KEY_LENGTH),
                chainCode, (short) 0, CHAIN_CODE_LENGTH);
    }


    private void deriveKey(APDU apdu) {
        if (masterKey == null) {
            ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
        }

        byte[] buffer = apdu.getBuffer();
        short bytesRead = apdu.setIncomingAndReceive();

        if (bytesRead < 1) {
            ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
        }

        byte[] currentPrivateKey = new byte[32];
        byte[] currentChainCode = new byte[32];

        // Derive the private key and chain code
        derivePrivateKey(buffer, ISO7816.OFFSET_CDATA, (byte)bytesRead,
                currentPrivateKey, currentChainCode);

        // Generate EC key pair from derived private key
        KeyPair keyPair = new KeyPair(KeyPair.ALG_EC_FP, KeyBuilder.LENGTH_EC_FP_256);
        ECPrivateKey privateKey = (ECPrivateKey) keyPair.getPrivate();
        ECPublicKey publicKey = (ECPublicKey) keyPair.getPublic();

        // Set the curve parameters and key value
        Secp256k1.setCommonCurveParameters(privateKey);
        Secp256k1.setCommonCurveParameters(publicKey);
        privateKey.setS(currentPrivateKey, (short) 0, (short) 32);

        // Generate the corresponding public key
        keyPair.genKeyPair();

        // Get the public key in uncompressed format
        byte[] publicKeyBuffer = new byte[65];
        short pubKeyLen = publicKey.getW(publicKeyBuffer, (short) 0);

        // Send both public key and chain code as response
        apdu.setOutgoing();
        apdu.setOutgoingLength((short)(pubKeyLen + 32));

        // First send public key
        apdu.sendBytesLong(publicKeyBuffer, (short) 0, pubKeyLen);
        // Then send chain code
        apdu.sendBytesLong(currentChainCode, (short) 0, (short) 32);
    }

    private void derivePrivateKey(byte[] path, short pathOffset, byte pathLength,
                                  byte[] privateKeyOut, byte[] chainCodeOut) {
        // Start with the master key and chain code
        Util.arrayCopyNonAtomic(masterKey, (short) 0, privateKeyOut, (short) 0, (short) 32);
        Util.arrayCopyNonAtomic(chainCode, (short) 0, chainCodeOut, (short) 0, (short) 32);

        byte[] derivationResult = new byte[64]; // Will hold both key and chain code

        // For each level in the path, derive a new key and chain code
        for (short i = 0; i < pathLength; i++) {
            byte pathIndex = path[(short)(pathOffset + i)];

            // Create input data for SHA-512
            Util.arrayCopyNonAtomic(privateKeyOut, (short) 0, tempBuffer, (short) 0, (short) 32);
            Util.arrayCopyNonAtomic(chainCodeOut, (short) 0, tempBuffer, (short) 32, (short) 32);
            tempBuffer[tempBuffer.length - 1] = pathIndex;

            // Generate 64 bytes with SHA-512
            sha.reset();
            sha.doFinal(tempBuffer, (short) 0, (short) tempBuffer.length, derivationResult, (short) 0);

            // First 32 bytes become the new private key
            Util.arrayCopyNonAtomic(derivationResult, (short) 0, privateKeyOut, (short) 0, (short) 32);
            // Second 32 bytes become the new chain code
            Util.arrayCopyNonAtomic(derivationResult, (short) 32, chainCodeOut, (short) 0, (short) 32);
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
