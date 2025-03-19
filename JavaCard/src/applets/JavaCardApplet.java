package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;

public class JavaCardApplet extends Applet implements MultiSelectable {

    // key derivation
    private static final byte INS_DERIVE_KEY = (byte) 0x55;

    // Example master key 
    private final byte[] masterKey = {
        (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04,
        (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08
    };

    // Buffer to store the derived key
    private byte[] derivedKey;
    private MessageDigest sha;

    public JavaCardApplet() {
        derivedKey = new byte[32];
        sha = MessageDigest.getInstance(MessageDigest.ALG_SHA, false);
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
            case INS_DERIVE_KEY:
                deriveKey(apdu);
                break;
            default:
                ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
        }
    }

    private void deriveKey(APDU apdu) {
        byte[] buffer = apdu.getBuffer();
        byte derivationIndex = buffer[ISO7816.OFFSET_CDATA];
        sha.reset();
        sha.update(masterKey, (short) 0, (short) masterKey.length);
        sha.update(new byte[]{ derivationIndex }, (short) 0, (short) 1);
        sha.doFinal(new byte[]{ derivationIndex }, (short) 0, (short) 1, derivedKey, (short) 0);
        apdu.setOutgoing();
        apdu.setOutgoingLength((short) derivedKey.length);
        apdu.sendBytesLong(derivedKey, (short) 0, (short) derivedKey.length);
    }

    public boolean select(boolean appInstAlreadyActive) {
        return true;
    }
    
    public void deselect(boolean appInstAlreadyActive) {
        // Optionally clear session data
    }
    
    public void deselect() {
        // Optionally clear session data
    }
}
