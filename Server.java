import java.math.BigInteger;
import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;

public class Server{
    //initialize socket and input stream
    private static ServerSocket server;
    private static Socket socket;
    private static BigInteger SID;
    private static String IDs;
    private static byte [] hashedKey;
    private static byte [] nonce;

    public Server(){
    }

    public static String getToken() {
        return  String.valueOf(System.currentTimeMillis()).substring(8, 13) + UUID.randomUUID().toString().substring(1,10);
    }

    
    public static void main(String [] args){
        try
        {
            // Server setup wait for client
            server = new ServerSocket(8080);
            System.out.println("Server started");
            System.out.println("Waiting for a client ...");
 
            socket = server.accept();

            System.out.println("Client Accepted");

            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            output.flush();
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

            System.out.println(input.readUTF()); // Receive client Hello message

            output.writeUTF("Server: Send Server's RSA Public Key");  // Server send RSA pkey
            output.flush();
            

            // Server's RSA generation
            RSAGenerator newRSA = new RSAGenerator();
            newRSA.genKeyRSA();
            RSA_PublicKeyPacket rsa_pkey = new RSA_PublicKeyPacket(newRSA.getN(), newRSA.getE());

            output.writeObject(rsa_pkey); // Send the RSA public key to client
            output.flush();

            System.out.println(input.readUTF()); // Receive client ID

            IDs = "Server" + getToken(); 

            String str = "Session" + getToken();
            SID = new BigInteger(str.getBytes());
            byte [] hSID = CryptoFunc.hashFunc(SID.toByteArray());
            BigInteger hashedSID = new BigInteger(hSID).abs();

            BigInteger signedSID = newRSA.generateSignature(hashedSID);
            ServerSessionID_Packet ssid = new ServerSessionID_Packet(hashedSID, IDs, signedSID);

            output.writeObject(ssid); // Send Server and Session ID to client
            output.flush();

            System.out.println("== Proceed to Diffie Hellman Key Exchange ==");
            // Diffie Hellman Key exchange
            DiffieHellman newDH = new DiffieHellman();
            BigInteger sX = CryptoFunc.randomBigInteger(BigInteger.ONE, newDH.getP().subtract(BigInteger.ONE));
            BigInteger exKey = newDH.calcExchangeKey(sX);                                       // Calc exchange key (k)
            hashedKey = CryptoFunc.hashFunc(exKey.toByteArray());                               // Calc hash of exchange key (k')
            BigInteger hKey = new BigInteger(hashedKey).abs();
            nonce = CryptoFunc.createNonce();                                                   // Generate new nonce
            BigInteger signedKey = newRSA.generateSignature(hKey);                              // Sign exchange key with RSA
            DHE_Packet_To_Client dhc = new DHE_Packet_To_Client(signedKey, exKey, nonce);      // Create DHE package to send to client

            output.writeObject(dhc); // Send DHE package to client
            output.flush();

            // Receive DH exchange key from client
            DHE_Packet_To_Server dhs = (DHE_Packet_To_Server) input.readObject();
            System.out.println("-- Proceed to calculate Share Key");
            BigInteger sharedKey = newDH.calcShareKey(dhs.getExchangeKey(), sX);
            byte [] hSharedKey = CryptoFunc.hashFunc(sharedKey.toByteArray());
            BigInteger hashedSharedKey = new BigInteger(hSharedKey).abs();  
            BigInteger signedSharedKey = newRSA.generateSignature(hashedSharedKey);
            DHE_Key_Confirmation_Packet dhkc = new DHE_Key_Confirmation_Packet(signedSharedKey);    // Create DHE Key confirmation packet

            output.writeObject(dhkc); // Send DHE Key Confirmation to client
            output.flush();

            System.out.println("== Proceed to Data Exchange ==");
            // Receive Data packet 1 from Client
            DataExchange_Packet dataEx1 = (DataExchange_Packet) input.readObject();
            byte [] chmac1 = dataEx1.getHMAC();
            byte [] shmac1 = CryptoFunc.HMAC(hSharedKey, dataEx1.getCipherText());
            if(Arrays.equals(chmac1, shmac1)) // Message Authentication Code HMAC verify
            {
                System.out.println("-- HMAC verification successfully");
                AESCBC newAES = new AESCBC();
                byte [] resizeKey = newAES.resizeKey(hSharedKey);
                SecretKey key = new SecretKeySpec(resizeKey, "AES");
                byte[] ivB = dataEx1.getIV();
                byte [] ciphertext1 = dataEx1.getCipherText();
                byte [] message1 = newAES.decrypt(ciphertext1, key, ivB); 
                System.out.println("Client: Message 1: "+ CryptoFunc.bytesToHex(message1));

                // Data exchange 2
                byte [] message2 = CryptoFunc.randomByteMessage();
                IvParameterSpec iv1 = newAES.genIV();
                byte[] ivE = iv1.getIV(); byte[] ivD = iv1.getIV();
                byte[] ciphertext2 = newAES.encrypt(message2, key, ivE);
                byte[] hmac2 = CryptoFunc.HMAC(hSharedKey, ciphertext2);
                DataExchange_Packet dataEx2 = new DataExchange_Packet(ciphertext2, hmac2, ivD);

                output.writeObject(dataEx2); // Send Data packet 2 to client
                output.flush();

                // Receive Data packet 3 from Client
                DataExchange_Packet dataEx3 = (DataExchange_Packet) input.readObject();
                byte [] chmac3 = dataEx3.getHMAC();
                byte [] shmac3 = CryptoFunc.HMAC(hSharedKey, dataEx3.getCipherText());
                if(Arrays.equals(chmac3, shmac3)) // Message Authentication Code HMAC verify
                {
                    System.out.println("-- HMAC verification successfully");
                    byte[] iv3 = dataEx3.getIV();
                    byte [] ciphertext3 = dataEx3.getCipherText();
                    byte [] message3 = newAES.decrypt(ciphertext3, key, iv3); 
                    System.out.println("Client: Message 3: "+ CryptoFunc.bytesToHex(message3));

                    // Data exchange 2
                    byte [] message4 = CryptoFunc.randomByteMessage();
                    IvParameterSpec iv4 = newAES.genIV();
                    byte[] ivD4 = iv4.getIV();
                    byte[] ciphertext4 = newAES.encrypt(message4, key, ivE);
                    byte[] hmac4 = CryptoFunc.HMAC(hSharedKey, ciphertext4);
                    DataExchange_Packet dataEx4 = new DataExchange_Packet(ciphertext4, hmac4, ivD4);

                    output.writeObject(dataEx4); // Send Data packet 4 to client
                    output.flush();
                    System.out.println("Data Exchange Completed. Session End.");

                }
                else{
                    System.err.println("-- HMAC verification failed. Session End");
                }
            }
            else{
                System.err.println("-- HMAC verification failed. Session End");
            }
            output.close(); input.close();
        }
        catch(IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException i)
        {
            i.printStackTrace();
        }
    }
}
