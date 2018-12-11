import javax.crypto.Mac;
import java.math.BigInteger;
import java.security.*;
import java.util.Arrays;
import java.util.Scanner;

/*
Implementation of authenticated DH Key Exchange
 */
public class Problem4 {

    private static BigInteger g;
    private static BigInteger p;

    public static void main(String[] args) throws SignatureException, NoSuchAlgorithmException, InvalidKeyException {
        genPG();
        genK();
    }

    //Generate large prime P and primitive root G
    private static void genPG() {
        System.out.println("Generating p, g. This will take a momemt...");
        SecureRandom s = new SecureRandom();
        BigInteger q;

        //Generate P
        do {
            q = BigInteger.probablePrime(2000, s);
            p = q.multiply(new BigInteger("2")).add(new BigInteger("1"));
        } while (!p.isProbablePrime(5));

        //Generate G
        do {
            g = new BigInteger(2000, s);
        } while (g.compareTo(p) > 0 && g.multiply(g).mod(p).equals(BigInteger.ONE));
    }

    private static void genK() throws NoSuchAlgorithmException, SignatureException, InvalidKeyException {
        SecureRandom s = new SecureRandom();
        //Generate exponent a
        BigInteger a = new BigInteger(2000, s);
        BigInteger b = new BigInteger(2000, s);
        //computer G^a
        BigInteger gA = g.modPow(a, p);
        BigInteger gB = g.modPow(b, p);

        //Generate keys
        KeyPairGenerator pair = KeyPairGenerator.getInstance("DSA");
        KeyPair keyA = pair.generateKeyPair();
        KeyPair keyB = pair.generateKeyPair();

        //Sign
        Signature sign = Signature.getInstance("Sha256withDSA");
        sign.initSign(keyA.getPrivate(), s);
        sign.update(gA.toByteArray());
        byte[] signA = sign.sign();

        sign.initSign(keyB.getPrivate(), s);
        sign.update(gB.toByteArray());
        byte[] signB = sign.sign();

        //Verify
        sign.initVerify(keyA.getPublic());
        sign.update(gA.toByteArray());
        if (!sign.verify(signA)) {
            System.out.println("Verification A failed");
            return;
        }
        sign.initVerify(keyB.getPublic());
        sign.update(gB.toByteArray());
        if (!sign.verify(signB)) {
            System.out.println("Verification B failed");
            return;
        }

        BigInteger alice = gB.modPow(a, p);
        BigInteger bob = gA.modPow(b, p);
        if (alice.compareTo(bob) == 0)
            System.out.println("Verification complete, key: " + alice.toString());
        else
            System.out.println("Values do not equal");
    }
}
