import java.math.BigInteger;
import java.util.Random;

public class RSAGenerator {
    private BigInteger e;
    private BigInteger p;
    private BigInteger q;
    private BigInteger d;
    private BigInteger n;

 
    public RSAGenerator(){
        e = new BigInteger("65537");
        p = BigInteger.ZERO;
        q = BigInteger.ZERO;
        d = BigInteger.ZERO;
        n = BigInteger.ZERO;

    }

    public void genKeyRSA(){
        Random rand1 = new Random(System.currentTimeMillis());
        Random rand2 = new Random(System.currentTimeMillis()*10);
        
        p = BigInteger.probablePrime(1024, rand1);
        q = BigInteger.probablePrime(1024, rand2);

        n = p.multiply(q);

        BigInteger p_1 = p.subtract(BigInteger.ONE);
        BigInteger q_1 = q.subtract(BigInteger.ONE);

        BigInteger z = p_1.multiply(q_1);

        d = e.modInverse(z);

    }

    public BigInteger generateSignature(BigInteger M){
        // Check if M < n
        if(M.compareTo(n) == 1 || M.compareTo(n) == 0){
            System.err.println("M is larger than n");
            System.exit(0);
        }

        return CryptoFunc.powMod2(M, d, n); // C = M^d (mod n)
    }

    public BigInteger verifySignature(BigInteger C, BigInteger publicKey, BigInteger n){
        return CryptoFunc.powMod2(C, publicKey, n); // M = C^e (mod n)
    }

    public BigInteger getN(){
        return n;
    }
    public BigInteger getE() { return e; }

    public static void main(String args[]) {
    }
}