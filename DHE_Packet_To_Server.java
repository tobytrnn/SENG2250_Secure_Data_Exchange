import java.io.Serializable;
import java.math.BigInteger;

public class DHE_Packet_To_Server implements Serializable{
    private BigInteger exchangeKey;
    private byte [] nonce;
    public DHE_Packet_To_Server(BigInteger exchangeKeyVal, byte[] nonceVal){
        exchangeKey = exchangeKeyVal;
        nonce = nonceVal;
    }
    public BigInteger getExchangeKey(){
        return exchangeKey;
    }
    public byte[] getNonce(){
        return nonce;
    }
}
