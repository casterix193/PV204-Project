package cardtools;

import java.security.MessageDigest;
import java.io.ByteArrayOutputStream;
import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class NostrClient {
    private static final byte CLA_BYTE = (byte) 0xB0;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_SIGN = (byte) 0xC0;
    private static final byte INS_GENERATE_KEY = (byte) 0xD4;
    
    // PIN verification and key generation
    private static final byte P1_DEFAULT = (byte) 0x00;
    private static final byte P2_DEFAULT = (byte) 0x00;
    
    // sign command
    private static final byte SIGN_P1_CURRENT_KEY = (byte) 0x00;
    private static final byte SIGN_P1_DERIVE = (byte) 0x01;
    private static final byte SIGN_P1_DERIVE_AND_MAKE_CURRENT = (byte) 0x02;
    
    private final CardManager cardManager;
    
    public NostrClient(CardManager cardManager) {
        this.cardManager = cardManager;
    }
    
    /**
     * Verifies the PIN with the card.
     * 
     * @param pin the PIN to verify
     * @return true if PIN verification was successful
     */
    public boolean verifyPin(byte[] pin) throws Exception {
        CommandAPDU verifyPinCmd = new CommandAPDU(CLA_BYTE, INS_VERIFY_PIN, P1_DEFAULT, P2_DEFAULT, pin);
        ResponseAPDU response = cardManager.transmit(verifyPinCmd);
        return response.getSW() == 0x9000;
    }
    
    /**
     * Generates a key on the card if needed.
     * 
     * @return true if key generation was successful
     */
    public boolean generateKey() throws Exception {
        CommandAPDU generateKeyCmd = new CommandAPDU(CLA_BYTE, INS_GENERATE_KEY, P1_DEFAULT, P2_DEFAULT);
        ResponseAPDU response = cardManager.transmit(generateKeyCmd);
        return response.getSW() == 0x9000;
    }
    
    /**
     * Signs a Nostr event using the current key.
     * 
     * @param eventJson the JSON representation of the event to sign
     * @return a NostrSignature object containing the public key and signature
     */
    public NostrSignature signEvent(String eventJson) throws Exception {
        // Hash using SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] eventHash = digest.digest(eventJson.getBytes("UTF-8"));
        
        // Sign hash witth card
        CommandAPDU signCmd = new CommandAPDU(CLA_BYTE, INS_SIGN, SIGN_P1_CURRENT_KEY, P2_DEFAULT, eventHash);
        ResponseAPDU response = cardManager.transmit(signCmd);
        
        if (response.getSW() != 0x9000) {
            throw new Exception("Signing failed with status: " + Integer.toHexString(response.getSW()));
        }
        
        byte[] responseData = response.getData();
        
        // Extract pubkey and signature
        if (responseData.length != 96) {
            throw new Exception("Invalid response length. Expected 96 bytes, got " + responseData.length);
        }
        
        byte[] pubKey = new byte[32];
        byte[] signature = new byte[64];
        
        System.arraycopy(responseData, 0, pubKey, 0, 32);
        System.arraycopy(responseData, 32, signature, 0, 64);
        
        return new NostrSignature(pubKey, signature);
    }
    
    /**
     * Signs a Nostr event using a derived key path.
     * 
     * @param eventJson the JSON representation of the event to sign
     * @param keyPath the key derivation path
     * @param makeCurrent whether to make the derived key the current key
     * @return a NostrSignature object containing the public key and signature
     */
    public NostrSignature signEventWithPath(String eventJson, byte[] keyPath, boolean makeCurrent) throws Exception {
        // Hash event with SHA-256
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        byte[] eventHash = digest.digest(eventJson.getBytes("UTF-8"));
        
        // Combine hash and key path
        ByteArrayOutputStream dataStream = new ByteArrayOutputStream();
        dataStream.write(eventHash);
        dataStream.write(keyPath);
        byte[] data = dataStream.toByteArray();
       
        byte p1 = makeCurrent ? SIGN_P1_DERIVE_AND_MAKE_CURRENT : SIGN_P1_DERIVE;
        
        // Sign hash using card 
        CommandAPDU signCmd = new CommandAPDU(CLA_BYTE, INS_SIGN, p1, P2_DEFAULT, data);
        ResponseAPDU response = cardManager.transmit(signCmd);
        
        if (response.getSW() != 0x9000) {
            throw new Exception("Signing failed with status: " + Integer.toHexString(response.getSW()));
        }
        
        byte[] responseData = response.getData();
        
        // Extract pubkey and signature
        if (responseData.length != 96) {
            throw new Exception("Invalid response length. Expected 96 bytes, got " + responseData.length);
        }
        
        byte[] pubKey = new byte[32];
        byte[] signature = new byte[64];
        
        System.arraycopy(responseData, 0, pubKey, 0, 32);
        System.arraycopy(responseData, 32, signature, 0, 64);
        
        return new NostrSignature(pubKey, signature);
    }
    
    /**
     * Class representing a Nostr signature, which includes both the public key and the signature.
     */
    public static class NostrSignature {
        private final byte[] publicKey;
        private final byte[] signature;
        
        public NostrSignature(byte[] publicKey, byte[] signature) {
            this.publicKey = publicKey;
            this.signature = signature;
        }
        
        public byte[] getPublicKey() {
            return publicKey;
        }
        
        public byte[] getSignature() {
            return signature;
        }
        
        public String getPublicKeyHex() {
            return bytesToHex(publicKey);
        }
        
        public String getSignatureHex() {
            return bytesToHex(signature);
        }
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b & 0xff));
        }
        return sb.toString();
    }
}