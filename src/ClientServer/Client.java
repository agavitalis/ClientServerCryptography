package ClientServer;

import java.io.*;
import java.net.Socket;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Client {
    public static void main(String[] args) throws Exception {
        try (Socket socket = new Socket("localhost", 2000)) {
            System.out.println("Client: connected to server.");
            
            // Key exchange
            KeyPair clientKP = Utils.generateDHKeyPair();
            SecretKey sharedSecret = performKeyExchange(socket, clientKP);
            
            // Mutual authentication
            if (!performMutualAuthentication(socket, sharedSecret)) {
                System.out.println("Authentication failed");
                return;
            }
            
            // Secure data transmission
            sendStudentData(socket, sharedSecret);
        }
    }

    private static SecretKey performKeyExchange(Socket socket, KeyPair clientKP) throws Exception {
        // Send client public key
        Utils.sendPublicKey(socket, clientKP.getPublic());
        
        // Receive server public key
        PublicKey serverPublicKey = Utils.receivePublicKey(socket);
        
        // Generate shared secret
        return Utils.generateSharedSecret(clientKP.getPrivate(), serverPublicKey);
    }

    private static boolean performMutualAuthentication(Socket socket, SecretKey key) throws Exception {
        // Server authentication
        String serverChallenge = Utils.receiveEncryptedMessage(socket, key);
        Utils.sendEncryptedMessage(socket, serverChallenge, key);
        
        // Client authentication
        String clientChallenge = Utils.generateChallenge();
        Utils.sendEncryptedMessage(socket, clientChallenge, key);
        String response = Utils.receiveEncryptedMessage(socket, key);
        
        return Utils.verifyChallenge(clientChallenge, response);
    }

    private static void sendStudentData(Socket socket, SecretKey key) throws Exception {
        Student student = new Student("Vitalis", "Ogbonna", 27);
        SealedObject sealedStudent = Utils.sealObject(student, key);
        
        ObjectOutputStream oos = new ObjectOutputStream(socket.getOutputStream());
        oos.writeObject(sealedStudent);
        System.out.println("Sent encrypted Student object");
    }
}