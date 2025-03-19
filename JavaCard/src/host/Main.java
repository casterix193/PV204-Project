package host;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import cardtools.CardManager;
import cardtools.RunConfig;
import cardtools.Util;
import applets.JavaCardApplet; 

public class Main {
    public static void main(String[] args) {
        System.out.println("Starting JavaCardApplet simulation...");
        try {
            // Define  AID 
            String APPLET_AID = "11223344556677889900"; 
            byte[] aidBytes = Util.hexStringToByteArray(APPLET_AID);
            
            CardManager cardManager = new CardManager(true, aidBytes);
            
            RunConfig runConfig = RunConfig.getDefaultConfig();
            runConfig.setAppletToSimulate(JavaCardApplet.class);
            runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
            
            System.out.print("Connecting to card simulator...");
            if (!cardManager.Connect(runConfig)) {
                System.out.println("Connection failed.");
                return;
            }
            System.out.println("Connected.");
            
            String deriveCommand = "B055010000";
            CommandAPDU command = new CommandAPDU(Util.hexStringToByteArray(deriveCommand));
            
            ResponseAPDU response = cardManager.transmit(command);
            byte[] responseData = response.getData();
            
            System.out.println("Derived Key from Simulator: " + Util.byteArrayToHexString(responseData));
            
            cardManager.Disconnect(true);
        } catch(Exception e) {
            e.printStackTrace();
        }
    }
}