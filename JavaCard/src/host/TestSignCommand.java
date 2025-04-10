package host;

import applets.KeycardApplet;
import cardtools.RunConfig;
import javacard.framework.ISO7816;
import cardtools.CardManager;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

public class TestSignCommand {

    // Replace with your applet's AID bytes.
    private static final byte[] APPLET_AID_BYTES = {
            (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
            (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C,
            (byte) 0x06
    };
    private static final byte CLA_BYTE = (byte) 0xB0;
    private static final byte INS_SIGN = (byte) 0xC0;

    private static final byte P1 = (byte) 0x00;
    private static final byte P2 = (byte) 0x00;

    private static final short EXPECTED_SIGNATURE_LENGTH = 64;

    public static void main(String[] args) throws Exception {
        CardManager cardManager = new CardManager(true, APPLET_AID_BYTES);

        RunConfig runConfig = RunConfig.getDefaultConfig();
        runConfig.setAppletToSimulate(KeycardApplet.class);
        runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);

        System.out.print("Connecting to card simulator...");
        if (!cardManager.Connect(runConfig)) {
            throw new Exception("Connection failed.");
        }

        byte[] command = new byte[ISO7816.OFFSET_CDATA + 32];
        command[ISO7816.OFFSET_CLA] = (byte) 0x00;
        command[ISO7816.OFFSET_INS] = INS_SIGN;
        command[ISO7816.OFFSET_P1] = P1;
        command[ISO7816.OFFSET_P2] = P2;
        command[ISO7816.OFFSET_LC] = 32;

        for (short i = ISO7816.OFFSET_CDATA; i < ISO7816.OFFSET_CDATA + 32; i++) {
            command[i] = (byte) 0x01;
        }

        CommandAPDU verifyPinApdu = new CommandAPDU(CLA_BYTE, INS_SIGN, P1, P2, command);

        // Transmit the command and obtain the response.
        ResponseAPDU response = cardManager.transmit(verifyPinApdu);
    }
}

