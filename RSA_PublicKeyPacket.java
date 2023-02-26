import java.io.Serializable;
import java.math.BigInteger;

public class RSA_PublicKeyPacket implements Serializable{
    private BigInteger e;
    private BigInteger n;
    public RSA_PublicKeyPacket(BigInteger nVal, BigInteger eVal){
        e = eVal;
        n = nVal;
    }
    public BigInteger getE(){
        return e;}
    public BigInteger getN(){
        return n;}
}