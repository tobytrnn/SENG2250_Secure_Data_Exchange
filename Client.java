import java.net.*;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.UUID;

import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import java.io.*;
import java.math.BigInteger;

public class Client{

    // initialize socket and input output streams
    private static Socket socket;
    private static String IDc;
    private static byte[] nonce;

    public Client()
    {
       
    }

    public static String getToken() {
        return  String.valueOf(System.currentTimeMillis()).substring(8, 13) + UUID.randomUUID().toString().substring(1,10);
    }

    public static void main(String [] args) {
        // establish a connection
        try
        {
            System.out.println("Connecting ...");
            socket = new Socket("localhost", 8080);

            //DataInputStream input = new DataInputStream(socket.getInputStream());
            //DataOutputStream output = new DataOutputStream(socket.getOutputStream());
            ObjectOutputStream output = new ObjectOutputStream(socket.getOutputStream());
            output.flush();
            ObjectInputStream input = new ObjectInputStream(socket.getInputStream());

            output.writeUTF("Client: Hello"); // Client send hello message
            output.flush(); 

            System.out.println(input.readUTF()); // Print Server's RSA Pkey */

            RSA_PublicKeyPacket rsa_PKey = (RSA_PublicKeyPacket) input.readObject(); // Receive the RSA_PKey object
            // Retrieve the n and e from the rsa pkey
            BigInteger n = rsa_PKey.getN();
            BigInteger e = rsa_PKey.getE();

            IDc = "Client" + getToken();

            // Send Client's ID to server
            output.writeUTF("Client: Client's ID is " + IDc);
            output.flush();

            // Receive Server's ID and SessionID with the signedSID (signed with RSA)
            ServerSessionID_Packet ssid = (ServerSessionID_Packet) input.readObject();
            // Verify the signed session key from Server
            RSAGenerator newRSA = new RSAGenerator();
            BigInteger signedSID = ssid.getSignedSID();
            BigInteger verifiedSID = newRSA.verifySignature(signedSID, e, n);

            if(ssid.getSID().equals(verifiedSID)){
                System.out.println("Server's digital signature verified");
                System.out.printf("Server: Server's ID is %s SessionID is %s \n", ssid.getIDs(), ssid.getSID());

                System.out.println("== Proceed to Diffie Hellman Key Exchange ==");
                DiffieHellman newDH = new DiffieHellman();
                BigInteger cX = CryptoFunc.randomBigInteger(BigInteger.ONE, newDH.getP().subtract(BigInteger.ONE));
                BigInteger exKey = newDH.calcExchangeKey(cX);                                   // Calc exchange key (k)
                nonce = CryptoFunc.createNonce();                                               // Generate new nonce
                DHE_Packet_To_Server dhs = new DHE_Packet_To_Server(exKey, nonce);        // Create DHE package to send to client

                output.writeObject(dhs); // Send DHE package to client
                output.flush();

                DHE_Packet_To_Client dhc = (DHE_Packet_To_Client) input.readObject(); // Receive DHE package from server
                //Verify Server's exchange key digital signature 
                BigInteger signedKey = dhc.getSignedKey();
                BigInteger verifiedKeySign = newRSA.verifySignature(signedKey, e, n);

                byte [] hashedKeyServer = CryptoFunc.hashFunc(dhc.getExchangeKey().toByteArray());
                BigInteger hKeyServer = new BigInteger(hashedKeyServer).abs();

                if(verifiedKeySign.equals(hKeyServer)){
                    System.out.println("-- Server's digital signature verified");
                    System.out.println("-- Proceed to calculate Share Key");
                    BigInteger sharedKey = newDH.calcShareKey(dhc.getExchangeKey(), cX);
                    byte [] hSharedKey = CryptoFunc.hashFunc(sharedKey.toByteArray());
                    BigInteger hashedSharedKey = new BigInteger(hSharedKey).abs();

                    // Receive DHE Key confirmation packet from server
                    DHE_Key_Confirmation_Packet dhkc = (DHE_Key_Confirmation_Packet) input.readObject(); 
                    BigInteger signedSharedKey = dhkc.getSignedSharedKey();
                    BigInteger verifiedSharedKey = newRSA.verifySignature(signedSharedKey, e, n);
                    // Confirm Key
                    if(verifiedSharedKey.equals(hashedSharedKey)){
                        System.out.println("-- Shared Key Confirmed");
                        System.out.println("== Proceed to Data Exchange ==");
                        AESCBC newAES = new AESCBC();
                        // Data Exchange 1
                        byte [] message1 = CryptoFunc.randomByteMessage();
                        byte [] resizeKey = newAES.resizeKey(hSharedKey);

                        SecretKey key = new SecretKeySpec(resizeKey, "AES");
                        IvParameterSpec iv1 = newAES.genIV();
                        byte[] ivE = iv1.getIV(); byte[] ivD = iv1.getIV();
                        byte[] ciphertext1 = newAES.encrypt(message1, key, ivE);
                        byte[] hmac1 = CryptoFunc.HMAC(hSharedKey, ciphertext1);
                        DataExchange_Packet dataEx1 = new DataExchange_Packet(ciphertext1, hmac1, ivD);

                        output.writeObject(dataEx1); // Send Data packet 1 to Server
                        output.flush();

                        // Receive Data packet 2 from Server
                        DataExchange_Packet dataEx2 = (DataExchange_Packet) input.readObject(); 
                        byte [] shmac1 = dataEx2.getHMAC();
                        byte [] chmac1 = CryptoFunc.HMAC(hSharedKey, dataEx2.getCipherText());
                        if(Arrays.equals(shmac1, chmac1)) // Message Authentication Code HMAC verify
                        {
                            System.out.println("-- HMAC verification successfully");
                            byte[] iv2 = dataEx2.getIV();
                            byte [] ciphertext2 = dataEx2.getCipherText();
                            byte [] message2 = newAES.decrypt(ciphertext2, key, iv2); 
                            System.out.println("Server: Message 2: "+ CryptoFunc.bytesToHex(message2));

                            // Data Exchange 3
                            byte [] message3 = CryptoFunc.randomByteMessage();
                            IvParameterSpec iv3 = newAES.genIV();
                            byte[] ivD3 = iv3.getIV();
                            byte[] ciphertext3 = newAES.encrypt(message3, key, ivE);
                            byte[] hmac3 = CryptoFunc.HMAC(hSharedKey, ciphertext3);
                            DataExchange_Packet dataEx3 = new DataExchange_Packet(ciphertext3, hmac3, ivD3);

                            output.writeObject(dataEx3); // Send Data packet 3 to Server
                            output.flush();

                            // Receive Data packet 4 from Server
                            DataExchange_Packet dataEx4 = (DataExchange_Packet) input.readObject(); 
                            byte [] shmac4 = dataEx4.getHMAC();
                            byte [] chmac4 = CryptoFunc.HMAC(hSharedKey, dataEx4.getCipherText());
                            if(Arrays.equals(shmac4, chmac4)) // Message Authentication Code HMAC verify
                            {
                                System.out.println("-- HMAC verification successfully");
                                byte[] iv4 = dataEx4.getIV();
                                byte [] ciphertext4 = dataEx4.getCipherText();
                                byte [] message4 = newAES.decrypt(ciphertext4, key, iv4); 
                                System.out.println("Server: Message 4: "+ CryptoFunc.bytesToHex(message4));
                                System.out.println("Data Exchange Completed. Session End.");
                            }
                            else{
                                System.out.println("-- HMAC verification failed. Session End.");
                            }
                        }
                        else
                        {
                            System.out.println("-- HMAC verification failed. Session End.");
                        }
                    }
                    else
                    {
                        System.err.println("-- Server's Key Confirmation failed. Session End.");
                    } 
                }       
                else
                {
                    System.err.println("-- Server's Exchange Key signature unverified. Session End.");
                }
            }
            else
            {
                System.err.println("-- Server's SID signature unverified. Session end");
                System.exit(0);
            }
            output.close(); input.close();
        } 
        catch(IOException | ClassNotFoundException | NoSuchAlgorithmException | NoSuchPaddingException e)
        {
            e.printStackTrace();
        } 
    }        
}
