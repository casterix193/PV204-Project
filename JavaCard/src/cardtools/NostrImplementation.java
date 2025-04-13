package cardtools;

import applets.KeycardApplet;

// Main class for demonstrating the Nostr event signing implementation using the JavaCard applet.
public class NostrImplementation {
    // AID of the KeycardApplet
    private static final byte[] APPLET_AID_BYTES = {
        (byte) 0xA0, (byte) 0x00, (byte) 0x00, (byte) 0x00,
        (byte) 0x62, (byte) 0x03, (byte) 0x01, (byte) 0x0C,
        (byte) 0x06
    };
    
    // Default PIN (6 digits)
    private static final byte[] DEFAULT_PIN = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36  // "123456"
    };
    
    // Init data for applet initialization (PIN and PUK)
    private static final byte[] INIT_DATA = {
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36,  // PIN: "123456"
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x31, 0x32, 0x33  // PUK: "123456789123"
    };
    
    public static void main(String[] args) {
        try {
            System.out.println("Starting Nostr event signing implementation");
            
            // Connect to card
            CardManager cardManager = new CardManager(true, APPLET_AID_BYTES);
            RunConfig runConfig = RunConfig.getDefaultConfig();
            runConfig.setAppletToSimulate(KeycardApplet.class);
            runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);
            runConfig.setInstallData(INIT_DATA);
            
            System.out.print("Connecting to card simulator... ");
            if (!cardManager.Connect(runConfig)) {
                throw new Exception("Connection failed");
            }
            System.out.println("Connected");
            
            // Create NostrClient
            NostrClient nostrClient = new NostrClient(cardManager);
            
            // Verify PIN
            System.out.print("Verifying PIN... ");
            if (!nostrClient.verifyPin(DEFAULT_PIN)) {
                throw new Exception("PIN verification failed");
            }
            System.out.println("PIN verified");
            
            // Generate key if needed
            System.out.print("Generating key... ");
            if (!nostrClient.generateKey()) {
                throw new Exception("Key generation failed");
            }
            System.out.println("Key generated");
            
            // Create Nostr event
            System.out.println("Creating Nostr event");
            NostrEvent event = new NostrEvent(1, "Hello Nostr from JavaCard!");
            
            // Sign the event
            System.out.print("Signing event... ");
            if (!event.sign(nostrClient)) {
                throw new Exception("Event signing failed");
            }
            System.out.println("Event signed");
            
            // Print the signed event
            System.out.println("Signed event:");
            System.out.println(event.toJson());
            
            // Create and sign a note with a reply
            System.out.println("\nCreating reply event");
            NostrEvent replyEvent = new NostrEvent(1, "This is a reply to the previous note!");
            replyEvent.addEventTag(event.getId());  
            replyEvent.addPubkeyTag(event.getPubkey());  
            
            System.out.print("Signing reply event... ");
            if (!replyEvent.sign(nostrClient)) {
                throw new Exception("Reply event signing failed");
            }
            System.out.println("Reply event signed");
            
            // Print the signed reply event
            System.out.println("Signed reply event:");
            System.out.println(replyEvent.toJson());
            
            // Show how to use derived keys 
            System.out.println("\nCreating event with derived key");
            NostrEvent derivedEvent = new NostrEvent(1, "This message was signed with a derived key!");
            
            // Create a sample derivation path (m/0)
            byte[] keyPath = new byte[]{0x00};
            
            System.out.print("Signing with derived key... ");
            if (!derivedEvent.signWithPath(nostrClient, keyPath, false)) {
                throw new Exception("Derived key signing failed");
            }
            System.out.println("Derived key event signed");
            
            // Print the signed derived event
            System.out.println("Signed event with derived key:");
            System.out.println(derivedEvent.toJson());
            
            // Disconnect from the card
            cardManager.Disconnect(true);
            System.out.println("\nDisconnected from card");
            
            // instructions for real-world use
            System.out.println("\nIMPORTANT: To use this with an actual Nostr client:");
            System.out.println("1. Take the JSON output from above");
            System.out.println("2. Send it to a Nostr relay using a client or API");
            System.out.println("3. Verify that the signature is accepted by the relay");
            
        } catch (Exception e) {
            System.err.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}