import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Scanner;

/*
Implementation of a hybrid encryption system.
 */
public class Problem5 {
    public static void main(String[] args) throws IllegalBlockSizeException, InvalidKeyException, BadPaddingException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeySpecException {
        System.out.println("Selection from the following options.\n1. Encrypt\n2. Decrypt");
        Scanner in = new Scanner(System.in);
        if (!in.hasNextInt())
            System.out.println("Not a valid option.");
        else {
            int choice = in.nextInt();
            if (choice == 1) {
                System.out.println("Enter the modulus: ");
                BigInteger modulus = new BigInteger(in.next(), 16);
                System.out.println("Enter the exponent: ");
                BigInteger exponent = new BigInteger(in.next(), 16);
                System.out.println("Enter the message: ");
                String message = in.next();
                encrypt(modulus, exponent, message);
            } else if (choice == 2) {
                System.out.println("Enter the modulus: ");
                BigInteger modulus = new BigInteger(in.next(), 16);
                System.out.println("Enter the exponent: ");
                BigInteger exponent = new BigInteger(in.next(), 16);
                System.out.println("Enter the cipher: ");
                BigInteger cipher = new BigInteger(in.next(), 16);
                System.out.println("Enter the key: ");
                BigInteger key = new BigInteger(in.next(), 16);
                decrypt(modulus, exponent, cipher, key);
            } else {
                System.out.println("Not a valid option.");
            }
        }
    }

    private static void encrypt(BigInteger modulus, BigInteger exponent, String message) throws NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException,
            InvalidKeySpecException {
        //Generate a symmetric session key
        KeyGenerator gen = KeyGenerator.getInstance("AES");
        SecretKey s = gen.generateKey();

        //Encrypt message with a CCA encryption scheme
        Cipher c = Cipher.getInstance("AES/GCM/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, s);
        byte[] result = c.doFinal(message.getBytes());

        //Encrypt the session key
        c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent)));
        byte[] keyEnc = c.doFinal(s.getEncoded());

        System.out.println("Encryption: " + new BigInteger(result));
        System.out.println("Key: " + new BigInteger(keyEnc));
    }

    public static void decrypt(BigInteger modulus, BigInteger exponent, BigInteger cipher, BigInteger key) throws NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, KeyFactory.getInstance("RSA").generatePrivate(new RSAPrivateKeySpec(modulus, exponent)));
        byte[] keyDec = c.doFinal(key.toByteArray());

        SecretKey s = new SecretKeySpec(keyDec, "AES");
        c = Cipher.getInstance("AES/GCM/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, s);
        byte[] m = c.doFinal(cipher.toByteArray());

        System.out.println("Message: " + Arrays.toString(m));
    }
}
