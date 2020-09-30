import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;

public class Gen {
    public static void main(String[] args) {
        
        try {
            // Create a key generator for RSA keys
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);

            // Generate Bob's public and private keys
            KeyPair bobPair = kpg.generateKeyPair();
            Key bobPublic = bobPair.getPublic();
            Key bobPrivate = bobPair. getPrivate();

            // Write Bob's private key
            String outFile = "bobPrivate";
            FileOutputStream out = new FileOutputStream(outFile + ".key");
            out.write(bobPrivate.getEncoded());
            out.close();

            // Write Bob's public key
            outFile = "bobPublic";
            out = new FileOutputStream(outFile + ".pub");
            out.write(bobPublic.getEncoded());
            out.close();

            // --------------------------------------------------------------------------

            // Generate Alice's public and private keys, then write them to files
            KeyPair alicePair = kpg.generateKeyPair();
            Key alicePublic = alicePair.getPublic();
            Key alicePrivate = alicePair.getPrivate();
            
            // Write Alice's private key
            outFile = "alicePrivate";
            out = new FileOutputStream(outFile + ".key");
            out.write(alicePrivate.getEncoded());
            out.close();

            // Write Alice's public key
            outFile = "alicePublic";
            out = new FileOutputStream(outFile + ".pub");
            out.write(alicePublic.getEncoded());
            out.close();

            // Get key formats
            // System.out.println("Public key format: " + alicePublic.getFormat());
            // System.out.println("Private key format: " + alicePrivate.getFormat());

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
