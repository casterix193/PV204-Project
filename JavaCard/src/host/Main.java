package host;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.spec.ECPublicKeySpec;
import java.util.ArrayList;
import java.util.List;
import cardtools.CardManager;
import cardtools.RunConfig;
import cardtools.Util;
import applets.JavaCardApplet;
import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.util.Arrays;


public class Main {
    // Constants
    private static final byte CLA_BYTE = (byte) 0xB0;
    private static final byte INS_VERIFY_PIN = (byte) 0x20;
    private static final byte INS_CHANGE_PIN = (byte) 0x21;
    private static final byte INS_DERIVE_KEY = (byte) 0x55;
    private static final byte INS_GENERATE_MASTER_KEY = (byte) 0x56;
    private static final byte INS_LOAD_MASTER_KEY = (byte) 0x57;
    private static final byte INS_SIGN_DATA = (byte) 0x59;

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
            runSigningTest(cardManager);
            //runGenerateAndDeriveKeyTest(cardManager);
            //runLoadCustomKeyTest(cardManager);
            //runHierarchicalDerivationTest(cardManager); // Add the new test
            //runPinTest(cardManager);

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
    
    private static final byte[] AES_KEY = {
        (byte) 0x01, (byte) 0x02, (byte) 0x03, (byte) 0x04,
        (byte) 0x05, (byte) 0x06, (byte) 0x07, (byte) 0x08,
        (byte) 0x09, (byte) 0x0A, (byte) 0x0B, (byte) 0x0C,
        (byte) 0x0D, (byte) 0x0E, (byte) 0x0F, (byte) 0x10
    };

    
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

    private static byte[] encryptData(byte[] data) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(AES_KEY, "AES"));

        return cipher.doFinal(Arrays.copyOf(data, 16)); 
    }

    private static void runSigningTest(CardManager cardManager) {
        try {
            System.out.println("\nTEST 4: Signing with derived keys");

            // Load a predictable master key
            byte[] testMasterKey = new byte[64];
            Arrays.fill(testMasterKey, (byte)0x44);
            CommandAPDU loadKeyApdu = new CommandAPDU(CLA_BYTE, INS_LOAD_MASTER_KEY, 0x00, 0x00, testMasterKey);
            ResponseAPDU response = cardManager.transmit(loadKeyApdu);
            if (!checkStatusWord(response, SW_SUCCESS)) {
                addTestResult("Signing Test - Setup", false, "Failed to load test master key");
                return;
            }

            // Test paths and test data
            byte[][] paths = {
                    {1},    // m/1
                    {1, 2}  // m/1/2
            };
            byte[] dataToSign = "Hello, world!".getBytes();

            // For each path: derive key, get public key, sign data, verify signature
            for (byte[] path : paths) {
                String pathStr = pathToString(path);

                // 1. Get public key for this path
                CommandAPDU deriveCmd = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x00, 0x00, path);
                response = cardManager.transmit(deriveCmd);
                if (!checkStatusWord(response, SW_SUCCESS)) {
                    addTestResult("Sign+Verify " + pathStr, false, "Failed to derive key");
                    continue;
                }

                byte[] responseData = response.getData();
                byte[] publicKey = Arrays.copyOfRange(responseData, 0, 65); // First 65 bytes = pubkey

                // 2. Sign data with this path
                System.out.println("\nSigning data with path " + pathStr);
                ByteArrayOutputStream signData = new ByteArrayOutputStream();
                signData.write(path.length);           // Path length
                signData.write(path);                  // Path indices
                signData.write(dataToSign);            // Data to sign (no length prefix)

                CommandAPDU signCmd = new CommandAPDU(CLA_BYTE, INS_SIGN_DATA, 0x00, 0x00, signData.toByteArray());
                response = cardManager.transmit(signCmd);

                if (!checkStatusWord(response, SW_SUCCESS)) {
                    addTestResult("Sign+Verify " + pathStr, false,
                            "Failed to sign with SW: 0x" + Integer.toHexString(response.getSW()));
                    continue;
                }

                byte[] signature = response.getData();
                addTestResult("Sign " + pathStr, true, "Signature length: " + signature.length);

                // 3. Verify signature (simpler approach)
                try {
                    boolean verified = verifySignature(dataToSign, signature, publicKey);
                    addTestResult("Verify " + pathStr, verified,
                            verified ? "Signature verified successfully" : "Signature verification failed");
                } catch (Exception e) {
                    addTestResult("Verify " + pathStr, false, "Verification exception: " + e.getMessage());
                }
            }
        } catch (Exception e) {
            addTestResult("Signing Test", false, "Exception: " + e.getMessage());
            e.printStackTrace();
        }
    }

    private static boolean verifySignature(byte[] data, byte[] signature, byte[] publicKey) throws Exception {
        ECPublicKeySpec keySpec = getEcPublicKeySpec(publicKey);
        java.security.KeyFactory keyFactory = java.security.KeyFactory.getInstance("EC");
        java.security.PublicKey pubKey = keyFactory.generatePublic(keySpec);


        java.security.Signature ecdsaVerify = java.security.Signature.getInstance("SHA256withECDSA");
        ecdsaVerify.initVerify(pubKey);
        ecdsaVerify.update(data);

        try {
            return ecdsaVerify.verify(signature);
        } catch (Exception e) {
            return false;
        }
    }


    private static ECPublicKeySpec getEcPublicKeySpec(byte[] publicKey) {
        if (publicKey[0] != 0x04 || publicKey.length != 65) {
            throw new IllegalArgumentException("Expected uncompressed public key (0x04|X|Y)");
        }

        // Extract X and Y coordinates
        byte[] x = Arrays.copyOfRange(publicKey, 1, 33);
        byte[] y = Arrays.copyOfRange(publicKey, 33, 65);

        // Create EC point and public key
        java.security.spec.ECPoint point = new java.security.spec.ECPoint(
                new java.math.BigInteger(1, x),
                new java.math.BigInteger(1, y));

        // Get secp256k1 parameters
        java.security.spec.ECParameterSpec params = getSecp256k1Params();
        ECPublicKeySpec keySpec = new ECPublicKeySpec(point, params);
        return keySpec;
    }

    // Keep the getSecp256k1Params method as before
    private static java.security.spec.ECParameterSpec getSecp256k1Params() {
        // These values are from the secp256k1 curve specification
        String pHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F";
        String aHex = "0000000000000000000000000000000000000000000000000000000000000000";
        String bHex = "0000000000000000000000000000000000000000000000000000000000000007";
        String gxHex = "79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798";
        String gyHex = "483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8";
        String nHex = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

        java.math.BigInteger p = new java.math.BigInteger(pHex, 16);
        java.math.BigInteger a = new java.math.BigInteger(aHex, 16);
        java.math.BigInteger b = new java.math.BigInteger(bHex, 16);
        java.math.BigInteger gx = new java.math.BigInteger(gxHex, 16);
        java.math.BigInteger gy = new java.math.BigInteger(gyHex, 16);
        java.math.BigInteger n = new java.math.BigInteger(nHex, 16);

        java.security.spec.ECFieldFp field = new java.security.spec.ECFieldFp(p);
        java.security.spec.EllipticCurve curve = new java.security.spec.EllipticCurve(field, a, b);
        java.security.spec.ECPoint g = new java.security.spec.ECPoint(gx, gy);

        return new java.security.spec.ECParameterSpec(curve, g, n, 1);
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
            byte[] plaintext = new byte[]{0x00}; // Data to send
            byte[] encryptedData = encryptData(plaintext); 

            CommandAPDU deriveCommandApdu = new CommandAPDU(CLA_BYTE, (byte) 0xA1, 0x00, 0x00, encryptedData);
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

            byte[] customKey = new byte[64];
            Arrays.fill(customKey, (byte) 0x33);
            verifyDefaultPin(cardManager);
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

    private static void runHierarchicalDerivationTest(CardManager cardManager) {
        try {
            System.out.println("\nTEST 3: Hierarchical Key Derivation");

            // Load a predictable master key
            byte[] testMasterKey = new byte[32];
            for (int i = 0; i < testMasterKey.length; i++) {
                testMasterKey[i] = (byte)0x44;
            }

            CommandAPDU loadKeyApdu = new CommandAPDU(CLA_BYTE, INS_LOAD_MASTER_KEY, 0x00, 0x00, testMasterKey);
            ResponseAPDU loadResponse = cardManager.transmit(loadKeyApdu);

            if (!checkStatusWord(loadResponse, SW_SUCCESS)) {
                addTestResult("Hierarchical Derivation - Setup", false, "Failed to load test master key");
                return;
            }

            // Test various paths and collect results
            byte[][] testPaths = {
                    {1},             // m/1
                    {2},             // m/2
                    {1, 1},          // m/1/1
                    {1, 2},          // m/1/2
                    {2, 1},          // m/2/1
                    {1, 1, 1, 1, 1}  // m/1/1/1/1/1 - deeper path
            };

            // Store derived keys for comparison
            byte[][] derivedKeys = new byte[testPaths.length][];

            // Test each path
            for (int i = 0; i < testPaths.length; i++) {
                String pathStr = pathToString(testPaths[i]);
                CommandAPDU deriveCommand = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x00, 0x00, testPaths[i]);
                ResponseAPDU response = cardManager.transmit(deriveCommand);

                if (checkStatusWord(response, SW_SUCCESS)) {
                    derivedKeys[i] = response.getData();
                    addTestResult("Derive " + pathStr, true,
                            "Key: " + Util.toHex(response.getData()).substring(0, 16) + "...");
                } else {
                    addTestResult("Derive " + pathStr, false,
                            "Failed with SW: 0x" + Integer.toHexString(response.getSW()));
                }
            }

            // Verify determinism by deriving same paths again
            for (int i = 0; i < testPaths.length; i++) {
                String pathStr = pathToString(testPaths[i]);
                CommandAPDU deriveCommand = new CommandAPDU(CLA_BYTE, INS_DERIVE_KEY, 0x00, 0x00, testPaths[i]);
                ResponseAPDU response = cardManager.transmit(deriveCommand);

                if (checkStatusWord(response, SW_SUCCESS)) {
                    boolean areEqual = java.util.Arrays.equals(derivedKeys[i], response.getData());
                    addTestResult("Deterministic " + pathStr, areEqual,
                            areEqual ? "Same path produced identical keys" : "FAILED: Same path produced different keys");
                }
            }

            // Compare keys from different paths to ensure uniqueness
            System.out.println("\nKey uniqueness verification:");
            for (int i = 0; i < derivedKeys.length; i++) {
                for (int j = i + 1; j < derivedKeys.length; j++) {
                    if (derivedKeys[i] != null && derivedKeys[j] != null) {
                        boolean areEqual = java.util.Arrays.equals(derivedKeys[i], derivedKeys[j]);
                        String pathI = pathToString(testPaths[i]);
                        String pathJ = pathToString(testPaths[j]);

                        addTestResult("Uniqueness " + pathI + " vs " + pathJ, !areEqual,
                                areEqual ? "FAILED: Different paths produced identical keys" :
                                        "Different paths correctly produced different keys");
                    }
                }
            }

        } catch (Exception e) {
            addTestResult("Hierarchical Derivation Test", false, "Exception: " + e.getMessage());
        }
    }

    // Helper method to convert path array to string representation
    private static String pathToString(byte[] path) {
        StringBuilder sb = new StringBuilder("m");
        for (byte b : path) {
            sb.append("/").append(Byte.toUnsignedInt(b));
        }
        return sb.toString();
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