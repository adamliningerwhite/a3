import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.KeyPair;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

            // --------------------------------------------------------------------------
            // TEMPORARY: MANUALLY GENERATE AND DISTRIBUTE k 
            KeyGenerator kg = KeyGenerator.getInstance("AES");
            kg.init(256);
            Key sharedKey = kg.generateKey();
            System.out.println("Shared key format: " + sharedKey.getFormat());  
            outFile = "sharedKey";
            out = new FileOutputStream(outFile + ".key");
            out.write(sharedKey.getEncoded());
            out.close();
            
            
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
