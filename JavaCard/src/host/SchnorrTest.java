package host;

import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

/**
 * Simple test class for Schnorr signature implementation
 */
public class SchnorrTest {
    // secp256k1 curve parameters
    private static final BigInteger p = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16);
    private static final BigInteger n = new BigInteger("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16);
    private static final BigInteger G_x = new BigInteger("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16);
    private static final BigInteger G_y = new BigInteger("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16);
    
    // Constants for calculation
    private static final BigInteger TWO = BigInteger.valueOf(2);
    private static final BigInteger THREE = BigInteger.valueOf(3);
    
    // Point addition on the secp256k1 curve
    private static BigInteger[] pointAdd(BigInteger[] P, BigInteger[] Q) {
        if (P == null) return Q;
        if (Q == null) return P;
        
        BigInteger x1 = P[0], y1 = P[1];
        BigInteger x2 = Q[0], y2 = Q[1];
        
        if (x1.equals(x2) && !y1.equals(y2)) {
            return null; // Point at infinity
        }
        
        BigInteger s;
        if (x1.equals(x2)) {
            // Point doubling
            s = x1.pow(2).multiply(THREE).multiply(
                y1.multiply(TWO).modPow(p.subtract(BigInteger.ONE), p)
            ).mod(p);
        } else {
            // Point addition
            s = y2.subtract(y1).multiply(
                x2.subtract(x1).modPow(p.subtract(BigInteger.ONE), p)
            ).mod(p);
        }
        
        BigInteger x3 = s.pow(2).subtract(x1).subtract(x2).mod(p);
        BigInteger y3 = s.multiply(x1.subtract(x3)).subtract(y1).mod(p);
        
        return new BigInteger[] {x3, y3};
    }
    
    // Scalar multiplication: k * P
    private static BigInteger[] pointMul(BigInteger k, BigInteger[] P) {
        BigInteger[] result = null;
        BigInteger[] addend = P;
        
        while (k.compareTo(BigInteger.ZERO) > 0) {
            if (k.testBit(0)) {
                result = pointAdd(result, addend);
            }
            addend = pointAdd(addend, addend);
            k = k.shiftRight(1);
        }
        
        return result;
    }
    
    // Simple Schnorr signature implementation
    public static byte[] schnorrSign(byte[] message, byte[] privateKeyBytes) {
        BigInteger privateKey = new BigInteger(1, privateKeyBytes);
        
        // 1. Generate a random nonce
        SecureRandom random = new SecureRandom();
        byte[] nonceBytes = new byte[32];
        random.nextBytes(nonceBytes);
        BigInteger k = new BigInteger(1, nonceBytes).mod(n);
        
        // 2. Compute R = k*G
        BigInteger[] G = new BigInteger[] {G_x, G_y};
        BigInteger[] R = pointMul(k, G);
        
        // 3. If R.y is odd, negate k
        if (R[1].testBit(0)) {
            k = n.subtract(k);
        }
        
        // 4. Compute e = H(R.x || pubKey || message)
        BigInteger[] pubKey = pointMul(privateKey, G);
        
        byte[] pubKeyBytes = pubKey[0].toByteArray();
        byte[] rX = R[0].toByteArray();
        
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            digest.update(rX);
            digest.update(pubKeyBytes);
            digest.update(message);
            byte[] eBytes = digest.digest();
            BigInteger e = new BigInteger(1, eBytes).mod(n);
            
            // 5. Compute s = k + e * privateKey
            BigInteger s = k.add(e.multiply(privateKey)).mod(n);
            
            // 6. The signature is (R.x || s)
            byte[] signature = new byte[64];
            byte[] rXPadded = padTo32(rX);
            byte[] sPadded = padTo32(s.toByteArray());
            
            System.arraycopy(rXPadded, 0, signature, 0, 32);
            System.arraycopy(sPadded, 0, signature, 32, 32);
            
            return signature;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }
    
    // Pad a byte array to 32 bytes
    private static byte[] padTo32(byte[] input) {
        byte[] result = new byte[32];

        // Handle the case where input might be longer than 32 bytes
        if (input.length > 32) {
            // If it's longer, copy only the rightmost 32 bytes
            int startPos = input.length - 32;
            System.arraycopy(input, startPos, result, 0, 32);
        } else {
            // If it's shorter, pad with zeros on the left
            int destPos = 32 - input.length;
            System.arraycopy(input, 0, result, destPos, input.length);
        }

        return result;
    }
    
    public static void main(String[] args) {
        try {
            // Test with a known private key
            byte[] privateKey = new byte[32];
            new SecureRandom().nextBytes(privateKey);
            
            // Test message
            String testMessage = "Hello, Schnorr!";
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] messageHash = digest.digest(testMessage.getBytes());
            
            // Sign the message
            byte[] signature = schnorrSign(messageHash, privateKey);
            
            // Print the results
            System.out.println("Private key: " + bytesToHex(privateKey));
            System.out.println("Message hash: " + bytesToHex(messageHash));
            System.out.println("Signature: " + bytesToHex(signature));
            
            // In a full implementation, we would verify the signature here
            System.out.println("Signature length: " + signature.length + " bytes");
            if (signature.length == 64) {
                System.out.println("Signature has the correct length");
            } else {
                System.out.println("Signature has incorrect length");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // Helper method to convert bytes to hex string
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02X", b));
        }
        return result.toString();
    }
}