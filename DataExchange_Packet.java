import java.io.Serializable;

public class DataExchange_Packet implements Serializable {
    private byte[] ciphertext;
    private byte[] hmac;
    private byte[] iv;
    public DataExchange_Packet(byte [] ciphertextVal, byte[] hmacVal, byte[] ivVal){
        ciphertext = ciphertextVal;
        hmac = hmacVal;
        iv = ivVal;
    }
    public byte [] getCipherText(){
        return ciphertext;
    }
    public byte [] getHMAC(){
        return hmac;
    }
    public byte[] getIV(){
        return iv;
    }
}
