import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Scanner;

/*
Implementation of the El Gamal Signature Scheme
 */
public class Problem1 {
    /*
    System parameters
    H: SHA-512, a collision resistant hash function
    p: a large prime
    g < p: a generator of the the group Zp* xmodp
     */
    private static MessageDigest H;
    private static BigInteger p;
    private static BigInteger g;

    public static void main(String[] args) throws NoSuchAlgorithmException {
        Scanner in = new Scanner(System.in);
        System.out.println("Select from the following options: \n1. Generate keys\n2. Generate Signature\n3. Verify Signature");
        if (!in.hasNextInt())
            System.out.println("Input was not valid.");
        else {

            int choice = in.nextInt();
            if (choice == 1) {
                System.out.println("Generating keys (This will take some time...)");
                genSys();
                keyGen();
            }
            else if (choice == 2) {
                System.out.println("Enter a message: ");
                String message = in.next();
                System.out.println("Enter a key: ");
                BigInteger x = new BigInteger(in.next(), 16);
                System.out.println("Enter a p: ");
                p = new BigInteger(in.next(), 16);
                System.out.println("Enter a g: ");
                g = new BigInteger(in.next(), 16);
                sign(message, x, p, g);
            }
            else if (choice == 3) {
                System.out.println("Enter the r of the signature: ");
                BigInteger r = new BigInteger(in.next(), 16);
                System.out.println("Enter the s of the signature: ");
                BigInteger s = new BigInteger(in.next(), 16);
                System.out.println("Enter the public key y of the signer: ");
                BigInteger y = new BigInteger(in.next(), 16);
                System.out.println("Enter a p: ");
                p = new BigInteger(in.next(), 16);
                System.out.println("Enter a g: ");
                g = new BigInteger(in.next(), 16);
                System.out.println("Enter the message: ");
                String m = in.next();
                verify(r, s, y, p, g, m);
            }
            else
                System.out.println("Number entered was not an option.");
        }
    }

    //Generate the global variables H, p, g
    private static void genSys() {
        //Generate group and large prime p
        SecureRandom s = new SecureRandom();
        BigInteger q;
        //Check to see that p and q are prime
        System.out.println("Generating p and q.");
        long time = System.currentTimeMillis();
        do {
            q = BigInteger.probablePrime(2000, s);
            p = q.multiply(new BigInteger("2")).add(new BigInteger("1"));
        } while (!p.isProbablePrime(5));
        System.out.println("Elapsed time for p and q: " + (System.currentTimeMillis() - time));

        //Generator for Zp* xmodp
        System.out.println("Generating g");
        time = System.currentTimeMillis();
        do {
            g = new BigInteger(2000, s);
        } while (g.compareTo(p) > 0 && g.multiply(g).mod(p).equals(BigInteger.ONE));
        System.out.println("Elapsed time for g: " + (System.currentTimeMillis() - time));
        System.out.println("P: " + p.toString(16));
        System.out.println("G: " + g.toString(16));
    }

    //Generate public and private keys y and x
    private static void keyGen() {
        //private key
        BigInteger x;
        SecureRandom s = new SecureRandom();

        //Generate key
        do {
            x = new BigInteger(2000, s);
        } while (!(x.compareTo(BigInteger.ONE) > 0 && x.compareTo(p.subtract(new BigInteger("2"))) < 0));

        //public key
        BigInteger y = g.modPow(x, p);


        System.out.println("Public key Y: " + y.toString(16));
        System.out.println("Private key X: " + x.toString(16));
    }

    //Generate signature (r, s) for message m under private key x
    private static void sign(String message, BigInteger x, BigInteger p, BigInteger g) throws NoSuchAlgorithmException {
        BigInteger k, r, s, temp1, temp2, temp3;
        SecureRandom sr = new SecureRandom();
        H = MessageDigest.getInstance("SHA-256");
        //Choose a random k such that 1 < k < p − 1 and gcd(k, p − 1) = 1.
        do {
            do {
                System.out.println("test");
                k = new BigInteger(2000, sr);
            } while (!k.gcd(p.subtract(BigInteger.ONE)).equals(BigInteger.ONE));

            //Compute r ≡ g^k (mod p)
            r = g.modPow(k, p);

            //Compute s ≡ (H(m) − xr)k^−1 (mod p−1)

            BigInteger m = new BigInteger(H.digest(message.getBytes()));

            System.out.println("test2");
            temp1 = m.subtract(x.multiply(r)).multiply(k.modInverse(p.subtract(BigInteger.ONE)));
            temp2 = temp1.mod(p.subtract(BigInteger.ONE));
            s = temp2;
        } while(s.equals(BigInteger.ZERO));

        System.out.println("R: " + r.toString(16));
        System.out.println("S: " + s.toString(16));
    }

    //Verify signature (r, s) for message m with public key y
    private static void verify(BigInteger r, BigInteger s, BigInteger y, BigInteger p, BigInteger g, String m) throws NoSuchAlgorithmException {
        H = MessageDigest.getInstance("SHA-256");

        //g^h(m) mod p
        BigInteger left = g.modPow(new BigInteger(H.digest(m.getBytes())), p);

        //y^r * r^s (mod p)
        BigInteger right = y.modPow(r, p).multiply(r.modPow(s, p)).mod(p);
        if (!(BigInteger.ZERO.compareTo(r) < 0 && r.compareTo(p) < 0))
            System.out.println("Invalid verification on 0 < r < p");
        else if (!(BigInteger.ZERO.compareTo(s) < 0 && s.compareTo(p.subtract(BigInteger.ONE)) < 0))
            System.out.println("Invalid verification on 0 < s < p - 1");
        else if (left.compareTo(right) == 0)
            System.out.println("Verification success");
        else
            System.out.println("Invalid verification on g^H(m) = y^r * r^s (mod p)");
    }
}
