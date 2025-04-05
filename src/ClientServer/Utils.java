package ClientServer;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.net.Socket;
import java.security.*;
import java.util.Random;

public class Utils {
    private static final String DH_ALGORITHM = "DH";
    private static final String AES_ALGORITHM = "AES";
    private static final String HMAC_ALGORITHM = "HmacSHA256";
    private static final String CIPHER_TRANSFORMATION = "AES/GCM/NoPadding";
    private static final int GCM_TAG_LENGTH = 128;
    private static final int AES_KEY_SIZE = 16;

    // Key exchange
    public static KeyPair generateDHKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance(DH_ALGORITHM);
        gen.initialize(2048);
        return gen.generateKeyPair();
    }

    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement agreement = KeyAgreement.getInstance(DH_ALGORITHM);
        agreement.init(privateKey);
        agreement.doPhase(publicKey, true);
        return agreement.generateSecret();
    }

    public static SecretKey deriveAESKey(byte[] sharedSecret, int offset) {
        return new SecretKeySpec(sharedSecret, offset, AES_KEY_SIZE, AES_ALGORITHM);
    }

    public static SecretKey deriveHMACKey(byte[] sharedSecret, int offset) {
        return new SecretKeySpec(sharedSecret, offset, AES_KEY_SIZE, HMAC_ALGORITHM);
    }

    // Message passing
    public static void sendMessage(Socket socket, String msg) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(msg);
        oos.flush();
    }

    public static String receiveMessage(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        return (String) ois.readObject();
    }

    public static void sendHMAC(Socket socket, byte[] hmac) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(hmac);
        oos.flush();
    }

    public static byte[] receiveHMAC(Socket socket) throws IOException, ClassNotFoundException {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        return (byte[]) ois.readObject();
    }

    public static byte[] generateHMAC(String message, SecretKey key) throws Exception {
        Mac mac = Mac.getInstance(HMAC_ALGORITHM);
        mac.init(key);
        return mac.doFinal(message.getBytes("UTF-8"));
    }

    public static String generateChallenge() {
        return Long.toString(System.currentTimeMillis()) + "-" + new Random().nextInt(999999);
    }

    // Sealing and Unsealing
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

    // Public key I/O
    public static void sendPublicKey(Socket socket, PublicKey publicKey) throws IOException {
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(publicKey);
        oos.flush();
    }

    public static PublicKey receivePublicKey(Socket socket) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        return (PublicKey) ois.readObject();
    }
}
