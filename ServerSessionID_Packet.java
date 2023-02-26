import java.io.Serializable;
import java.math.BigInteger;

public class ServerSessionID_Packet implements Serializable{
    private BigInteger SID; // session ID
    private String IDs; // server's ID
    private BigInteger signedSID;
    public ServerSessionID_Packet(BigInteger SIDVal, String IDsVal, BigInteger signedSIDVal){
        SID = SIDVal;
        IDs = IDsVal;
        signedSID = signedSIDVal;
    }
    public BigInteger getSID(){
        return SID;}
    public String getIDs(){
        return IDs;}
    public BigInteger getSignedSID(){
        return signedSID;}
}
