import java.io.Serializable;
import java.math.BigInteger;

public class DHE_Key_Confirmation_Packet implements Serializable{
    private BigInteger signedSharedKey; 
    DHE_Key_Confirmation_Packet(BigInteger signedSharedKeyVal){
        signedSharedKey = signedSharedKeyVal;
    }
    public BigInteger getSignedSharedKey(){
        return signedSharedKey;
    }
}
