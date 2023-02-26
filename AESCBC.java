import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

public class AESCBC{

    SecureRandom sRandom;

    public AESCBC(){
        try {
            sRandom = SecureRandom.getInstanceStrong();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public IvParameterSpec genIV() throws NoSuchAlgorithmException, NoSuchPaddingException{
        byte[] iv = new byte[16];
        sRandom.nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) {
        try {
            //byte[] IV = iv.getIV();
            byte[] keyBytes = key.getEncoded();
            
            if(plaintext.length % 16 !=0)
                throw new IllegalArgumentException("Invalid plaintext size");

            if(keyBytes.length!=(192/Byte.SIZE))
                throw new IllegalArgumentException("Key length must be 192"); 

            byte[] ciphertext = new byte[plaintext.length];

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.ENCRYPT_MODE, key); 
            
            int blockSize = 16; // init block size default to 16
            int numberOfBlock = plaintext.length / blockSize; // calc number of blocks in the plaintext

            // CBC encryption
            for(int i = 0; i < numberOfBlock; i++){
                int start = i * blockSize;
                byte[] temp = new byte[blockSize];

                // xor step: xor each byte in IV with the next plaintext block
                for(int j = 0; j < blockSize; j++){
                    temp[j] = (byte) (IV[j] ^ plaintext[j+start]);
                }
                temp = cipher.doFinal(temp); //encrypt

                // Copy the xor to IV, 
                // Replace IV with the most recent encrypted plaintext block
                for(int j = 0; j < IV.length; j++){ 
                    IV[j] = temp[j];
                }

                // Append each encrypted block to the whole ciphertext
                for(int j = 0; j < blockSize; j ++){
                    ciphertext[start+j] = temp[j]; 
                }
                
            }

            return ciphertext;
            
        } catch(InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e){
            throw new RuntimeException(e);
        }
    }

    public byte[] decrypt(byte[] ciphertext, SecretKey key, byte[] IV){
        try {
            //byte [] IV = iv.getIV();    // init IV bytes
            byte[] keyBytes = key.getEncoded();
            
            if(ciphertext.length % 16 !=0)  // Check for valid text size
                throw new IllegalArgumentException("Invalid ciphertext size");

            if(keyBytes.length!=(192/Byte.SIZE)) // Check for valid key size
                throw new IllegalArgumentException("Key length must be 192"); 

            byte[] plaintext = new byte[ciphertext.length];

            Cipher cipher = Cipher.getInstance("AES/ECB/NoPadding");
            cipher.init(Cipher.DECRYPT_MODE, key); //decrypt
            
            int blockSize = 16;
            int numberOfBlock = ciphertext.length / blockSize;

            // CBC decryption 
            for(int i = 0; i < numberOfBlock; i++){
                int start = i * blockSize;
                byte[] temp = new byte[blockSize];

                for(int j = 0; j < blockSize; j++){         // Copy ciphertext to a temp arr
                    temp[j] = ciphertext[j+start];
                }

                temp = cipher.doFinal(temp);                //decrypt the copied ciphertext block
                                                            
                for(int j = 0; j < blockSize; j++){         // xor step: xor each byte in IV with the recent decrypted ciphertext block
                    temp[j] = (byte) (IV[j] ^ temp[j]);
                }
                                                            // Copy this ciphertext block to IV, 
                for(int j = 0; j < IV.length; j++){         // Replace IV with this ciphertext block
                    IV[j] = ciphertext[j+start];
                }

                for(int j = 0; j < blockSize;j ++){         // Append each decrypted block to the whole plaintext
                    plaintext[j+start] = temp[j]; 
                }
            }
            return plaintext;
            
        } catch(InvalidKeyException | IllegalBlockSizeException | BadPaddingException | NoSuchAlgorithmException | NoSuchPaddingException e){
            throw new RuntimeException(e);
        }
    }

    // This function take the first 192bits in 256 bits hashed key
    public byte [] resizeKey(byte [] originalKey){
        byte [] key192 = new byte[24];
        // 192 bits = 24 bytes
        for(int i=0; i < 24 ; i++){
            key192[i] = originalKey[i];
        }
        return key192;
    }   

    public static void main(String [] args) throws NoSuchAlgorithmException, NoSuchPaddingException, IOException{
    }
}