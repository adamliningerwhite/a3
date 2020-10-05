import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.KeyPair;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;


public class Gen {
    public static void main(String[] args) {
        
        try {

            // Create a key generator for RSA keys
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024, SecureRandom.getInstance("SHA1PRNG"));

            // --------------------------------------------------------------------------

            // Generate Bob's public and private keys
            KeyPair bobPair = kpg.generateKeyPair();
            PublicKey bobPublic = bobPair.getPublic();
            PrivateKey bobPrivate = bobPair. getPrivate();

            // Write Bob's private key to file
            PKCS8EncodedKeySpec bobPrivateSpec = new PKCS8EncodedKeySpec(
				bobPrivate.getEncoded());
            String outFile = "bobPrivate";
            FileOutputStream out = new FileOutputStream(outFile + ".key");
            out.write(bobPrivateSpec.getEncoded());
            out.close();

            // Write Bob's public key to file
            X509EncodedKeySpec bobPublicSpec = new X509EncodedKeySpec(
				bobPublic.getEncoded());
            outFile = "bobPublic";
            out = new FileOutputStream(outFile + ".key");
            out.write(bobPublicSpec.getEncoded());
            out.close();

            // --------------------------------------------------------------------------

            // Generate Alice's public and private keys, then write them to files
            KeyPair alicePair = kpg.generateKeyPair();
            PublicKey alicePublic = alicePair.getPublic();
            PrivateKey alicePrivate = alicePair.getPrivate();
        
            // Write Alice's private key to file
            PKCS8EncodedKeySpec alicePrivateSpec = new PKCS8EncodedKeySpec(
				alicePrivate.getEncoded());
            outFile = "alicePrivate";
            out = new FileOutputStream(outFile + ".key");
            out.write(alicePrivateSpec.getEncoded());
            out.close();

            // Write Alice's public key to file
            X509EncodedKeySpec alicePublicSpec = new X509EncodedKeySpec(
				alicePublic.getEncoded());
            outFile = "alicePublic";
            out = new FileOutputStream(outFile + ".key");
            out.write(alicePublicSpec.getEncoded());
            out.close();

            // Get key formats
            System.out.println("Private key format: " + alicePrivate.getFormat());
            System.out.println("Public key format: " + alicePublic.getFormat());
            
        }
        catch (IOException e) {
            System.out.println("Error writing keys to files.");
            System.out.println(e.getMessage());
        }
        catch (NoSuchAlgorithmException e) {
            System.out.println("Error creating key generator");
            System.out.println(e.getMessage());
        }
    }
}
