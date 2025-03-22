package host;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.util.ArrayList;
import java.util.List;
import cardtools.CardManager;
import cardtools.RunConfig;
import cardtools.Util;
import applets.JavaCardApplet;

public class Main {
    // Constants
    private static final byte CLA_BYTE = (byte) 0xB0;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;
    private static final byte INS_DERIVE_KEY = (byte) 0x55;
    private static final byte INS_GENERATE_MASTER_KEY = (byte) 0x56;
    private static final byte INS_LOAD_MASTER_KEY = (byte) 0x57;

    // Default PIN "1234" in bytes
    private static final byte[] DEFAULT_PIN = {0x31, 0x32, 0x33, 0x34};
    private static final String APPLET_AID = "11223344556677889900";

    // Expected status words
    private static final int SW_SUCCESS = 0x9000;
    private static final int SW_SECURITY_STATUS_NOT_SATISFIED = 0x6982;

    // Test result tracking
    private static class TestResult {
        final String testName;
        final boolean passed;
        final String message;

        TestResult(String testName, boolean passed, String message) {
            this.testName = testName;
            this.passed = passed;
            this.message = message;
        }
    }

    private static final List<TestResult> testResults = new ArrayList<>();

    public static void main(String[] args) {
        System.out.println("Starting JavaCardApplet simulation...");
        CardManager cardManager = null;

        try {
            cardManager = setupCardManager();

            // Run tests
            verifyDefaultPin(cardManager);
            runGenerateAndDeriveKeyTest(cardManager);
            runLoadCustomKeyTest(cardManager);
            runDeterministicDerivationTest(cardManager);
            runPinTest(cardManager);

        } catch(Exception e) {
            addTestResult("Setup", false, "Fatal error: " + e.getMessage());
            e.printStackTrace();
        } finally {
            // Display test result summary
            displayTestSummary();

            // Disconnect from card
            if (cardManager != null) {
                try {
                    cardManager.Disconnect(true);
                } catch (Exception e) {
                    System.err.println("Error disconnecting from card: " + e.getMessage());
                }
            }
        }
    }

    private static void addTestResult(String testName, boolean passed, String message) {
        testResults.add(new TestResult(testName, passed, message));
        // Print immediate feedback as well
        System.out.println((passed ? "[PASS] " : "[FAIL] ") + testName +
                (message != null && !message.isEmpty() ? ": " + message : ""));
    }

    private static void displayTestSummary() {
        int total = testResults.size();
        int passed = 0;
        List<String> failures = new ArrayList<>();

        for (TestResult result : testResults) {
            if (result.passed) {
                passed++;
            } else {
                failures.add(result.testName + ": " + result.message);
            }
        }

        System.out.println("\n=== TEST SUMMARY ===");
        System.out.println("Total tests: " + total);
        System.out.println("Passed: " + passed);
        System.out.println("Failed: " + (total - passed));

        if (!failures.isEmpty()) {
            System.out.println("\nFailed tests:");
            for (String failure : failures) {
                System.out.println("  - " + failure);
            }
        }

        if (passed == total) {
            System.out.println("\nALL TESTS PASSED!");
        }
    }

    private static CardManager setupCardManager() throws Exception {
        byte[] aidBytes = Util.hexStringToByteArray(APPLET_AID);
        CardManager cardManager = new CardManager(true, aidBytes);

        RunConfig runConfig = RunConfig.getDefaultConfig();
        runConfig.setAppletToSimulate(JavaCardApplet.class);
        runConfig.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL);

        System.out.print("Connecting to card simulator...");
        if (!cardManager.Connect(runConfig)) {
            throw new Exception("Connection failed.");
        }
        System.out.println("Connected.");

        return cardManager;
    }

    private static void verifyDefaultPin(CardManager cardManager) {
        try {
            System.out.println("\nVerifying PIN before executing tests...");
            CommandAPDU verifyPinApdu = new CommandAPDU(CLA_BYTE, INS_VERIFY_PIN, 0x00, 0x00, DEFAULT_PIN);
            ResponseAPDU response = cardManager.transmit(verifyPinApdu);

            if (response.getSW() == SW_SUCCESS) {
                addTestResult("Default PIN Verification", true, "PIN verified successfully");
            } else {
                addTestResult("Default PIN Verification", false,
                        "Expected SW: 0x" + Integer.toHexString(SW_SUCCESS) +
                                ", Got: 0x" + Integer.toHexString(response.getSW()));
            }
        } catch (Exception e) {
            addTestResult("Default PIN Verification", false, "Exception: " + e.getMessage());
        }
    }

    private static void runGenerateAndDeriveKeyTest(CardManager cardManager) {
        try {
            System.out.println("\nTEST 1: Generate and derive key");

            // Generate key
            CommandAPDU generateKeyApdu = new CommandAPDU(CLA_BYTE, INS_GENERATE_MASTER_KEY, 0x01, 0x00);
            ResponseAPDU responseGenerate = cardManager.transmit(generateKeyApdu);
            System.out.println("Generate key response: " + Util.toHex(responseGenerate.getBytes()));

            boolean generateSuccess = checkStatusWord(responseGenerate, SW_SUCCESS);
            addTestResult("Generate Master Key", generateSuccess,
                    generateSuccess ? null : "Expected SW: 0x" + Integer.toHexString(SW_SUCCESS) +
                            ", Got: 0x" + Integer.toHexString(responseGenerate.getSW()));

            // Derive key
            CommandAPDU deriveCommandApdu = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x01, 0x00, new byte[]{0x00});
            ResponseAPDU responseDerive = cardManager.transmit(deriveCommandApdu);
            System.out.println("Derive key response: " + Util.toHex(responseDerive.getBytes()));

            boolean deriveSuccess = checkStatusWord(responseDerive, SW_SUCCESS) && responseDerive.getData().length == 32;
            addTestResult("Derive Key", deriveSuccess,
                    deriveSuccess ? "Derived key: " + Util.toHex(responseDerive.getData()) :
                            "Failed to derive key or incorrect derived key length");
        } catch (Exception e) {
            addTestResult("Generate and Derive Key Test", false, "Exception: " + e.getMessage());
        }
    }

    private static void runLoadCustomKeyTest(CardManager cardManager) {
        try {
            System.out.println("\nTEST 2: Load custom key and derive");

            byte[] customKey = new byte[32];
            for (int i = 0; i < customKey.length; i++) {
                customKey[i] = (byte)0x33;
            }

            CommandAPDU loadKeyApdu = new CommandAPDU(CLA_BYTE, INS_LOAD_MASTER_KEY, 0x01, 0x00, customKey);
            ResponseAPDU responseLoad = cardManager.transmit(loadKeyApdu);
            System.out.println("Load key response: " + Util.toHex(responseLoad.getBytes()));

            boolean loadSuccess = checkStatusWord(responseLoad, SW_SUCCESS);
            addTestResult("Load Custom Key", loadSuccess,
                    loadSuccess ? null : "Expected SW: 0x" + Integer.toHexString(SW_SUCCESS) +
                            ", Got: 0x" + Integer.toHexString(responseLoad.getSW()));

            CommandAPDU deriveCommandApdu = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x01, 0x00, new byte[]{0x00});
            ResponseAPDU responseDerive = cardManager.transmit(deriveCommandApdu);

            boolean deriveSuccess = checkStatusWord(responseDerive, SW_SUCCESS) && responseDerive.getData().length == 32;
            addTestResult("Derive From Custom Key", deriveSuccess,
                    deriveSuccess ? "Derived key: " + Util.toHex(responseDerive.getData()) :
                            "Failed to derive key from custom key");
        } catch (Exception e) {
            addTestResult("Load Custom Key Test", false, "Exception: " + e.getMessage());
        }
    }

    private static void runDeterministicDerivationTest(CardManager cardManager) {
        try {
            System.out.println("\nTEST 3: Verify deterministic key derivation");

            byte[] deterministicKey = new byte[32];
            for (int i = 0; i < deterministicKey.length; i++) {
                deterministicKey[i] = (byte)0x11;
            }

            // Load key
            CommandAPDU loadKeyApdu = new CommandAPDU(CLA_BYTE, INS_LOAD_MASTER_KEY, 0x01, 0x00, deterministicKey);
            ResponseAPDU loadResponse = cardManager.transmit(loadKeyApdu);
            boolean loadSuccess = checkStatusWord(loadResponse, SW_SUCCESS);
            addTestResult("Load Deterministic Key", loadSuccess, null);

            if (!loadSuccess) return;

            // First derivation
            CommandAPDU deriveCommand1 = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x01, 0x00, new byte[]{0x01});
            ResponseAPDU firstDerive = cardManager.transmit(deriveCommand1);
            boolean firstDeriveSuccess = checkStatusWord(firstDerive, SW_SUCCESS);

            if (!firstDeriveSuccess) {
                addTestResult("First Derivation", false, "Failed with SW: 0x" +
                        Integer.toHexString(firstDerive.getSW()));
                return;
            }

            // Second derivation (same index)
            ResponseAPDU secondDerive = cardManager.transmit(deriveCommand1);
            boolean secondDeriveSuccess = checkStatusWord(secondDerive, SW_SUCCESS);

            if (!secondDeriveSuccess) {
                addTestResult("Second Derivation", false, "Failed with SW: 0x" +
                        Integer.toHexString(secondDerive.getSW()));
                return;
            }

            // Check if identical
            boolean areEqual = java.util.Arrays.equals(firstDerive.getData(), secondDerive.getData());
            addTestResult("Deterministic Key Derivation", areEqual,
                    areEqual ? "Same index produced identical keys" :
                            "Same index produced different keys");

            // Different index derivation
            CommandAPDU deriveCommand2 = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x01, 0x00, new byte[]{0x02});
            ResponseAPDU differentDerive = cardManager.transmit(deriveCommand2);
            boolean diffDeriveSuccess = checkStatusWord(differentDerive, SW_SUCCESS);

            if (!diffDeriveSuccess) {
                addTestResult("Different Index Derivation", false, "Failed with SW: 0x" +
                        Integer.toHexString(differentDerive.getSW()));
                return;
            }

            // Check if different
            boolean areDifferent = !java.util.Arrays.equals(firstDerive.getData(), differentDerive.getData());
            addTestResult("Different Index Derivation", areDifferent,
                    areDifferent ? "Different indices produced different keys" :
                            "Different indices incorrectly produced identical keys");
        } catch (Exception e) {
            addTestResult("Deterministic Derivation Test", false, "Exception: " + e.getMessage());
        }
    }

    private static void runPinTest(CardManager cardManager) {
        try {
            System.out.println("\nTEST 4: PIN management");

            // Test incorrect PIN
            System.out.println("\nTest 4.1: Incorrect PIN handling");
            byte[] incorrectPin = {0x00, 0x00, 0x00, 0x00};
            CommandAPDU incorrectPinApdu = new CommandAPDU(CLA_BYTE, INS_VERIFY_PIN, 0x00, 0x00, incorrectPin);
            ResponseAPDU incorrectResponse = cardManager.transmit(incorrectPinApdu);
            int sw = incorrectResponse.getSW();
            int remainingTries = sw & 0x000F;

            // Expected: 0x63CX where X is remaining tries (should be 4 after one failed attempt)
            boolean correctErrorFormat = ((sw & 0xFFF0) == 0x63C0) && remainingTries > 0;
            addTestResult("Incorrect PIN Response", correctErrorFormat,
                    correctErrorFormat ? "Correct error format with " + remainingTries + " tries remaining" :
                            "Wrong error format, got: 0x" + Integer.toHexString(sw));

            // Verify correct PIN
            CommandAPDU correctPinApdu = new CommandAPDU(CLA_BYTE, INS_VERIFY_PIN, 0x00, 0x00, DEFAULT_PIN);
            ResponseAPDU correctResponse = cardManager.transmit(correctPinApdu);
            addTestResult("Correct PIN Verification", checkStatusWord(correctResponse, SW_SUCCESS),
                    "Expected SW: 0x" + Integer.toHexString(SW_SUCCESS) +
                            ", Got: 0x" + Integer.toHexString(correctResponse.getSW()));

            // Change PIN
            byte[] newPin = {0x35, 0x36, 0x37, 0x38}; // "5678"
            CommandAPDU changePinApdu = new CommandAPDU(CLA_BYTE, INS_CHANGE_PIN, 0x00, 0x00, newPin);
            ResponseAPDU changeResponse = cardManager.transmit(changePinApdu);
            addTestResult("Change PIN", checkStatusWord(changeResponse, SW_SUCCESS),
                    "Expected SW: 0x" + Integer.toHexString(SW_SUCCESS) +
                            ", Got: 0x" + Integer.toHexString(changeResponse.getSW()));

            // Test PIN required for operations
            // Reset connection to clear PIN validation state
            cardManager.Disconnect(false);
            cardManager = setupCardManager();

            // Try operation without PIN - should fail
            CommandAPDU generateKeyApdu = new CommandAPDU(CLA_BYTE, INS_GENERATE_MASTER_KEY, 0x01, 0x00);
            ResponseAPDU responseWithoutPin = cardManager.transmit(generateKeyApdu);
            boolean securityCheck = responseWithoutPin.getSW() == SW_SECURITY_STATUS_NOT_SATISFIED;
            addTestResult("Security Check Without PIN", securityCheck,
                    securityCheck ? "Correctly rejected operation without PIN" :
                            "Expected SW: 0x" + Integer.toHexString(SW_SECURITY_STATUS_NOT_SATISFIED) +
                                    ", Got: 0x" + Integer.toHexString(responseWithoutPin.getSW()));


            // Operation should now succeed with PIN
            verifyDefaultPin(cardManager);
            ResponseAPDU responseWithPin = cardManager.transmit(generateKeyApdu);
            addTestResult("Operation With PIN", checkStatusWord(responseWithPin, SW_SUCCESS),
                    "Expected SW: 0x" + Integer.toHexString(SW_SUCCESS) +
                            ", Got: 0x" + Integer.toHexString(responseWithPin.getSW()));

        } catch (Exception e) {
            addTestResult("PIN Management Test", false, "Exception: " + e.getMessage());
        }
    }

    private static boolean checkStatusWord(ResponseAPDU response, int expectedSW) {
        return response.getSW() == expectedSW;
    }
}