package ClientServer;

import java.io.*;
import java.net.*;
import java.security.*;
import javax.crypto.*;

public class Server {
    public static void main(String[] args) throws Exception {
        try (ServerSocket serverSocket = new ServerSocket(2000)) {
            System.out.println("Server: waiting for connection...");

            while (true) {
                try (Socket socket = serverSocket.accept()) {
                    System.out.println("Server: client connected.");

                    KeyPair serverKP = Utils.generateDHKeyPair();
                    byte[] sharedBytes = performKeyExchange(socket, serverKP);

                    SecretKey encryptionKey = Utils.deriveAESKey(sharedBytes, 0);
                    SecretKey hmacKey = Utils.deriveHMACKey(sharedBytes, 16);

                    if (performMutualAuthentication(socket, hmacKey)) {
                        receiveStudentData(socket, encryptionKey);
                    } else {
                        System.out.println("Authentication failed");
                    }
                }
            }
        }
    }

    private static byte[] performKeyExchange(Socket socket, KeyPair serverKP) throws Exception {
        Utils.sendPublicKey(socket, serverKP.getPublic());
        PublicKey clientPub = Utils.receivePublicKey(socket);
        return Utils.generateSharedBytes(serverKP.getPrivate(), clientPub);
    }

    private static boolean performMutualAuthentication(Socket socket, SecretKey hmacKey) throws Exception {
        String serverChallenge = Utils.generateChallenge();
        Utils.sendMessage(socket, serverChallenge);
        byte[] hmacResponse = Utils.receiveHMAC(socket);

        String clientChallenge = Utils.receiveMessage(socket);
        byte[] clientExpectedHmac = Utils.generateHMAC(clientChallenge, hmacKey);
        Utils.sendHMAC(socket, clientExpectedHmac);

        return MessageDigest.isEqual(hmacResponse, Utils.generateHMAC(serverChallenge, hmacKey));
    }

    private static void receiveStudentData(Socket socket, SecretKey encryptionKey) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(socket.getInputStream());
        SealedObject sealed = (SealedObject) ois.readObject();
        Student student = (Student) Utils.unsealObject(sealed, encryptionKey);
        System.out.println("Received Student: " + student);
    }
}
