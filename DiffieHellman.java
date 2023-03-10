import java.io.IOException;
import java.math.BigInteger;

public class DiffieHellman {
    private BigInteger p;
    private BigInteger g;
    private BigInteger exchangeKey;
    private BigInteger sharedKey;

    public DiffieHellman(){
        p = new BigInteger("178011905478542266528237562450159990145232156369120674273274450314442865788737020770612695252123463079567156784778466449970650770920727857050009668388144034129745221171818506047231150039301079959358067395348717066319802262019714966524135060945913707594956514672855690606794135837542707371727429551343320695239");
        g = new BigInteger("174068207532402095185811980123523436538604490794561350978495831040599953488455823147851597408940950725307797094915759492368300574252438761037084473467180148876118103083043754985190983472601550494691329488083395492313850000361646482644608492304078721818959999056496097769368017749273708962006689187956744210730");

        exchangeKey = BigInteger.ZERO;
        sharedKey = BigInteger.ZERO;
    }

    // Function to calculate its public key g^x mod p 
    public BigInteger calcExchangeKey(BigInteger x){
        exchangeKey = CryptoFunc.powMod2(g, x, p);
        return exchangeKey;
    }

    public BigInteger calcShareKey(BigInteger y, BigInteger x){
        sharedKey = CryptoFunc.powMod2(y, x, p);
        return sharedKey;
    }

    public BigInteger getP(){
        return p;
    }
    public BigInteger getG(){
        return g;
    }

    public static void main(String[] args) throws IOException{
    }   
} 
