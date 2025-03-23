package host;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;

public class SecureChannel {
    // a default 128-bit AES key (for demo only)
    private static final byte[] DEFAULT_AES_KEY = {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
        (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10
    };

    private SecretKeySpec keySpec;
    private Cipher cipher;

    /**
     * Constructor initializes the AES key and cipher
     * Using "AES/ECB/NoPadding" for simplicity; in production,
     * considering to use CBC mode with a proper IV.
     */
    public SecureChannel() throws Exception {
        keySpec = new SecretKeySpec(DEFAULT_AES_KEY, "AES");
        cipher = Cipher.getInstance("AES/ECB/NoPadding");
    }

    /**
     * Encrypt data using AES
     * Data is padded with zeros if not a multiple of 16 bytes.
     */
    public byte[] encrypt(byte[] data) throws Exception {
        byte[] paddedData = padData(data);
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return cipher.doFinal(paddedData);
    }

    /**
     * Decrypt data using AES
     */
    public byte[] decrypt(byte[] encryptedData) throws Exception {
        cipher.init(Cipher.DECRYPT_MODE, keySpec);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        return unpadData(decryptedData);
    }

    // Pad the data with zeros to the next multiple of 16 bytes
    private byte[] padData(byte[] data) {
        int blockSize = 16;
        int paddedLength = ((data.length + blockSize - 1) / blockSize) * blockSize;
        byte[] padded = new byte[paddedLength];
        System.arraycopy(data, 0, padded, 0, data.length);
        // remaining bytes are zero by default
        return padded;
    }

    private byte[] unpadData(byte[] data) {
        int i = data.length;
        while (i > 0 && data[i - 1] == 0) {
            i--;
        }
        return Arrays.copyOf(data, i);
    }
}
