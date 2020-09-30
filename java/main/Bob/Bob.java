import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class Bob {
	
	// Constants for RSA keys
	private static String PUBLIC_KEY_PATH = "bobPublic.pub";
	private static String PRIVATE_KEY_PATH = "bobPrivate.key";
	private static String PUBLIC_KEY_FORMAT = "X.509";
	private static String PRIVATE_KEY_FORMAT = "PKCS#8";

	//RSA keys 
	private PrivateKey privateKey;
	private PublicKey publicKey;

    //instance variables      
    private boolean mac;
    private boolean enc;

    public Base64.Encoder encoder = Base64.getEncoder();
    public Base64.Decoder decoder = Base64.getDecoder();

    public Bob(String bobPort, String config) throws Exception {

        //Apply configuration                                                 
        if(config.compareTo("noCrypto") == 0){
            mac = false;
            enc = false;
        } else if(config.compareTo("enc") == 0){
            mac = false;
            enc = true;
        } else if(config.compareTo("mac") == 0){
            mac = true;
            enc = false;
        } else if(config.compareTo("EncThenMac") == 0){
            mac = true;
            enc = true;
		}
		
		// Read in RSA keys 
		readKeys();

		//notify the identity of the server to the user
		System.out.println("This is Bob");
	
		//attempt to create a server with the given port number
		int portNumber = Integer.parseInt(bobPort);
		try {
			ServerSocket bobServer = new ServerSocket(portNumber);
			System.out.println("Bob Server started at port "+portNumber);
			
			//accept the client(a.k.a. Mallory)
			Socket clientSocket = bobServer.accept();
			System.out.println("Mallory connected");
			DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
				
			boolean finished = false;
				
			//read input from Mallory
			while(!finished) {
				try {
					String incomingMsg = streamIn.readUTF();
					// Split it into the message body and message number 
					String[] pieces = incomingMsg.split(":");
					String msg = pieces[0];
					String msgNum = pieces[1];

					System.out.println("Alice says: " + incomingMsg);
					
					finished = msg.equals("done");
				}
				catch(IOException ioe) {
					//disconnect if there is an error reading the input
					finished = true;
				}
			}
			//clean up the connections before closing
			bobServer.close();
			streamIn.close();
			System.out.println("Bob closed");
		} 
		catch (IOException e) {
			//print error if the server fails to create itself
			System.out.println("Error in creating the server");
			System.out.println(e);
		}
    }
	
	private void readKeys() {
		try {
			/* Read all bytes from the private key file */
			Path path = Paths.get(PRIVATE_KEY_PATH);
			byte[] bytes = Files.readAllBytes(path);

			/* Generate private key. */
			PKCS8EncodedKeySpec ks1 = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			privateKey = kf.generatePrivate(ks1);

			/* Read all the public key bytes */
			path = Paths.get(PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate public key. */
			X509EncodedKeySpec ks2 = new X509EncodedKeySpec(bytes);
			kf = KeyFactory.getInstance("RSA");
			publicKey = kf.generatePublic(ks2);
		}
		catch (IOException e) {
			System.out.println(e.getMessage());
		} 
		catch (NoSuchAlgorithmException e) {
			System.out.println(e.getMessage());
		} 
		catch (InvalidKeySpecException e) {
			System.out.println(e.getMessage());
		} 
	}

    /**
     * args[0] ; port where Bob expects connection (from Mallory)
     * args[1] ; program configuration
     */
    public static void main(String[] args) {
		//check for correct # of parameters
		if (args.length != 2) {
			System.out.println("Incorrect number of parameters");
			return;
		}
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		//create Bob
		try {
			Bob bob = new Bob(args[0], args[1]);
		} 
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
    }
}
