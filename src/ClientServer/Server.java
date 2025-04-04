package ClientServer;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;
import javax.crypto.spec.*;

public class Server {
    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(2000)) {
            System.out.println("Server: waiting for connection...");
            
            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    System.out.println("Server: client connected.");
                    
                    // Key exchange
                    KeyPair serverKP = Utils.generateDHKeyPair();
                    SecretKey sharedSecret = performKeyExchange(socket, serverKP);
                    
                    // Mutual authentication
                    if (!performMutualAuthentication(socket, sharedSecret)) {
                        System.out.println("Authentication failed");
                        continue;
                    }
                    
                    // Receive and process student data
                    receiveStudentData(socket, sharedSecret);
                }
            }
        }
    }

    private static SecretKey performKeyExchange(Socket socket, KeyPair serverKP) throws Exception {
        // Send server public key
        Utils.sendPublicKey(socket, serverKP.getPublic());
        
        // Receive client public key
        PublicKey clientPublicKey = Utils.receivePublicKey(socket);
        
        // Generate shared secret
        return Utils.generateSharedSecret(serverKP.getPrivate(), clientPublicKey);
    }

    private static boolean performMutualAuthentication(Socket socket, SecretKey key) throws Exception {
        // Server authentication
        String serverChallenge = Utils.generateChallenge();
        Utils.sendEncryptedMessage(socket, serverChallenge, key);
        String response = Utils.receiveEncryptedMessage(socket, key);
        
        if (!Utils.verifyChallenge(serverChallenge, response)) {
            return false;
        }
        
        // Client authentication
        String clientChallenge = Utils.receiveEncryptedMessage(socket, key);
        Utils.sendEncryptedMessage(socket, clientChallenge, key);
        
        return true;
    }

    private static void receiveStudentData(Socket socket, SecretKey key) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        SealedObject sealedStudent = (SealedObject) ois.readObject();
        
        Student student = (Student) Utils.unsealObject(sealedStudent, key);
        System.out.println("Received Student: " + student);
    }
}