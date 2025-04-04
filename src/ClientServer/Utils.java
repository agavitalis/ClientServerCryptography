package ClientServer;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.Random;

public class Utils {
    // Cryptographic constants
    private static final String DH_ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_SIZE = 16;
    private static final int DH_KEY_SIZE = 2048;

    //================ DH Key Exchange Methods ================//
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyGen.initialize(DH_KEY_SIZE);
        return keyGen.generateKeyPair();
    }

    public static KeyPair generateDHKeyPair(DHParameterSpec params) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        keyGen.initialize(params);
        return keyGen.generateKeyPair();
    }

    public static SecretKey generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance(DH_ALGORITHM);
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        byte[] sharedSecret = keyAgreement.generateSecret();
        return new SecretKeySpec(sharedSecret, 0, AES_KEY_SIZE, AES_ALGORITHM);
    }

    //================ Secure Communication Methods ================//
    public static SealedObject sealObject(Serializable obj, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, new byte[12]));
        return new SealedObject(obj, cipher);
    }

    public static Object unsealObject(SealedObject sealedObj, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, new byte[12]));
        return sealedObj.getObject(cipher);
    }

    //================ Authentication Methods ================//
    public static String generateChallenge() {
        return Long.toString(System.currentTimeMillis()) + "-" + new Random().nextInt(100000);
    }

    public static boolean verifyChallenge(String challenge, String response) {
        return challenge.equals(response);
    }

    //================ Network I/O Methods ================//
    public static void sendPublicKey(Socket socket, PublicKey publicKey) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(publicKey);
        oos.flush();
    }

    public static PublicKey receivePublicKey(Socket socket) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        return (PublicKey) ois.readObject();
    }

    public static void sendEncryptedMessage(Socket socket, String message, SecretKey key) throws Exception {
        byte[] encrypted = encryptString(message, key);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(encrypted);
        oos.flush();
    }

    public static String receiveEncryptedMessage(Socket socket, SecretKey key) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        byte[] encrypted = (byte[]) ois.readObject();
        return decryptString(encrypted, key);
    }

    //================ Core Crypto Methods ================//
    private static byte[] encryptString(String plaintext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.ENCRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, new byte[12]));
        return cipher.doFinal(plaintext.getBytes("UTF-8"));
    }

    private static String decryptString(byte[] ciphertext, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance(CIPHER_TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, key, new GCMParameterSpec(GCM_TAG_LENGTH, new byte[12]));
        byte[] decrypted = cipher.doFinal(ciphertext);
        return new String(decrypted, "UTF-8");
    }
}