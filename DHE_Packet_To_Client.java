import java.io.Serializable;
import java.math.BigInteger;

public class DHE_Packet_To_Client implements Serializable{
    private BigInteger signedKey;
    private BigInteger exchangeKey;
    private byte [] nonce;
    public DHE_Packet_To_Client(BigInteger signedKeyVal, BigInteger exchangeKeyVal, byte[] nonceVal){
        signedKey = signedKeyVal;
        exchangeKey = exchangeKeyVal;
        nonce = nonceVal;
    }
    public BigInteger getSignedKey(){
        return signedKey;
    }
    public BigInteger getExchangeKey(){
        return exchangeKey;
    }
    public byte[] getNonce(){
        return nonce;
    }
}
