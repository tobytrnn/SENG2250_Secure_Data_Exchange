import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

public class CryptoFunc {
    private static SecureRandom rand = new SecureRandom();

    public static BigInteger powMod2(BigInteger base, BigInteger expo, BigInteger n){
        if(n == BigInteger.ONE)
            return BigInteger.ZERO;
        BigInteger result = BigInteger.ONE;
        int x = expo.compareTo(BigInteger.ZERO);
        BigInteger one = BigInteger.ONE;
        while(x == 1){
            x = expo.compareTo(BigInteger.ZERO);
            if(((expo.and(one)).equals(one)))
                result = (result.multiply(base)).mod(n);
            expo = expo.shiftRight(1);
            base = (base.multiply(base)).mod(n);
        }
        return result;
    }

    public static BigInteger randomBigInteger(BigInteger minBound, BigInteger maxBound){
        BigInteger bigInteger = maxBound.subtract(minBound);
        int len = maxBound.bitLength();
        BigInteger res = new BigInteger(len, rand);
        if (res.compareTo(minBound) < 0)
            res = res.add(minBound);
        if (res.compareTo(bigInteger) >= 0)
            res = res.mod(bigInteger).add(minBound);
        return res;
    }

    public static byte[] hashFunc(byte [] message){
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] result = digest.digest(message);
            return result;
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        System.err.println("Hashed failed");
        return new byte [0];
    }

    public static String bytesToHex(byte[] hash) {
        StringBuilder hexString = new StringBuilder(2 * hash.length);
        for (int i = 0; i < hash.length; i++) {
            String hex = Integer.toHexString(0xff & hash[i]);
            if(hex.length() == 1) {
                hexString.append('0');
            }
            hexString.append(hex);
        }
        return hexString.toString();
    }

    public static byte[] HMAC(byte[] key, byte[] m){
        // H(k, m) = H((k xor opad) || H((k xor ipad) || m))
        byte opadBit = 0x5c;
        byte ipadBit = 0x36;
        byte[] opadComplete = new byte[key.length];
        byte[] ipadComplete = new byte[key.length];
        for(int i=0;i<key.length;i++) {
            opadComplete[i] = (byte) (opadBit ^ key[i]);
            ipadComplete[i] = (byte) (ipadBit ^ key[i]);
        }

        byte[] ipadConcatM = concat(ipadComplete, m);
        byte[] hashedIPad = CryptoFunc.hashFunc(ipadConcatM);
        byte [] result = concat(opadComplete, hashedIPad);
        return CryptoFunc.hashFunc(result);
    }

    // Concatenating function
    public static byte[] concat(byte[] A, byte[] B) {
        byte[] newArr = new byte[A.length+B.length];
        for(int i=0;i<A.length;i++) {
            newArr[i] = A[i];
        }

        for(int i=0;i<B.length;i++) {
            newArr[i+A.length] = B[i];
        }

        return newArr;
    }

    public static byte[] createNonce() {
        byte [] nonce = new byte[0];

        try {
            SecureRandom prng = SecureRandom.getInstance("SHA1PRNG");
            String randomNum = String.valueOf(prng.nextInt());

            MessageDigest sha = MessageDigest.getInstance("SHA-1");
            nonce = sha.digest(randomNum.getBytes());
            return nonce;
        } catch (Exception e) {
        }

        return nonce;
    }

    public static byte [] randomByteMessage(){
        Random rd = new Random();
        byte[] arr = new byte[64];
        rd.nextBytes(arr);
        return arr;
    }
}
