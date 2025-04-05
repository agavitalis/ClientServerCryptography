package ClientServer;

import java.io.*;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;

public class Client {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("localhost", 2000)) {
            System.out.println("Client: connected to server.");
            
            // Key exchange
            KeyPair clientKP = Utils.generateDHKeyPair();
            byte[] sharedBytes = performKeyExchange(socket, clientKP);

            SecretKey encryptionKey = Utils.deriveAESKey(sharedBytes, 0);
            SecretKey hmacKey = Utils.deriveHMACKey(sharedBytes, 16);

            // Mutual authentication
            if (!performMutualAuthentication(socket, hmacKey)) {
                System.out.println("Authentication failed");
                return;
            }

            // Secure data transmission
            sendStudentData(socket, encryptionKey);
        }
    }

    private static byte[] performKeyExchange(Socket socket, KeyPair clientKP) throws Exception {
        Utils.sendPublicKey(socket, clientKP.getPublic());
        PublicKey serverPub = Utils.receivePublicKey(socket);
        return Utils.generateSharedBytes(clientKP.getPrivate(), serverPub);
    }

    private static boolean performMutualAuthentication(Socket socket, SecretKey hmacKey) throws Exception {
        String serverChallenge = Utils.receiveMessage(socket);
        byte[] hmac = Utils.generateHMAC(serverChallenge, hmacKey);
        Utils.sendHMAC(socket, hmac);

        String clientChallenge = Utils.generateChallenge();
        Utils.sendMessage(socket, clientChallenge);
        byte[] responseHmac = Utils.receiveHMAC(socket);

        return MessageDigest.isEqual(hmac, Utils.generateHMAC(serverChallenge, hmacKey)) &&
               MessageDigest.isEqual(responseHmac, Utils.generateHMAC(clientChallenge, hmacKey));
    }

    private static void sendStudentData(Socket socket, SecretKey encryptionKey) throws Exception {
        Student student = new Student("Vitalis", "Ogbonna", 27);
        SealedObject sealed = Utils.sealObject(student, encryptionKey);
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(sealed);
        System.out.println("Sent encrypted Student object");
    }
}
