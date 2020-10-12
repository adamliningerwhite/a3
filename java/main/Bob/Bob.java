import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.Signature;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.*;

public class Bob {
	
	// Constants for RSA keys
	private static final String BOB_PUBLIC_KEY_PATH = "bobPublic.key";
	private static final String BOB_PRIVATE_KEY_PATH = "bobPrivate.key";
	private static final String ALICE_PUBLIC_KEY_PATH = "alicePublic.key";
	private static final String PUBLIC_KEY_FORMAT = "X.509";
	private static final String PRIVATE_KEY_FORMAT = "PKCS#8";

	// keys for encryption and integrity
	private static SecretKey sharedKey;
	private static SecretKey macKey;
	private static SecretKey decryptionKey;

	// RSA keys
	private RSAPrivateKey bobPrivateKey;
	private RSAPublicKey bobPublicKey;
	private RSAPublicKey alicePublicKey;

    // instance variables      
    private boolean mac;
    private boolean enc;

	// utilities 
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
			
			String keyTransportMessage = streamIn.readUTF();
			String keyResult = processTransport(keyTransportMessage);
			System.out.println(keyResult);
				
			//read input from Mallory
			boolean finished = false;
			while(!finished && keyResult == "Key Received") {
				try {
					// Read incoming message from mallory
					String incomingMsg = streamIn.readUTF();
					
					/* If in mac configuration, read another message and check tag */
					boolean macRes = !mac; 
					if(mac) {
						String mac = incomingMsg; // mac is first string we read 
						incomingMsg = streamIn.readUTF(); // actual message is 2nd string 
						macRes = macCheck(incomingMsg, mac); // check the tag 
						if(!macRes) {  // if given a bad tag, quit the program 
							System.out.println("ALERT: Mac tag didn't match. Mesage integrity compromised!! ");
							System.out.println("----------------------------------------------");
						} else {
							System.out.println("Mac string verified");
						}
					}
					
					/* Decrypt message (if applicable) */
					if(enc) {
						incomingMsg = decrypt(incomingMsg);
					}

					if(macRes) {
						System.out.println("Alice says: " + incomingMsg);
						System.out.println("----------------------------------------------");
					} 	
					
					finished = incomingMsg.equals("done");
				}
				catch(IOException ioe) {
					//disconnect if there is an error reading the input
					ioe.printStackTrace();
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

	/**
	 * Read relevant keys from files and save them in instance variables
	 * 
	 * For bob, we read: 
	 * 		1. His private RSA key 
	 * 		2. His public RSA key 
	 * 		3. Alice's public RSA key
	 * 
	 */
	private void readKeys() {
		try {
			/* Read all bytes from Bob's private key file */
			Path path = Paths.get(BOB_PRIVATE_KEY_PATH);
			byte[] bytes = Files.readAllBytes(path);

			/* Generate Bob's private key. */
			PKCS8EncodedKeySpec ks1 = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			bobPrivateKey = (RSAPrivateKey) kf.generatePrivate(ks1);

			// --------------------------------------------------------------------------

			/* Read all Bob's public key bytes */
			path = Paths.get(BOB_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate Bob's public key. */
			X509EncodedKeySpec ks2 = new X509EncodedKeySpec(bytes);
			bobPublicKey = (RSAPublicKey) kf.generatePublic(ks2);

			// --------------------------------------------------------------------------

			/* Read all Alice's public key bytes */
			path = Paths.get(ALICE_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate Alice's public key. */
			X509EncodedKeySpec ks3 = new X509EncodedKeySpec(bytes);
			alicePublicKey = (RSAPublicKey) kf.generatePublic(ks3);

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
	 * A method to verify Alice's signature over a message 
	 */
	private boolean signature(String piece, String signed) throws Exception{
		
		// Create and initialize signature
		Signature sign = Signature.getInstance("SHA256withRSA");
		sign.initVerify(alicePublicKey);  // Use alice's public key since we want to verify her sign

		// Add data to be verified
		sign.update(piece.getBytes());
		// Verify that the signature matches 
		boolean res = sign.verify(decoder.decode(signed));

		return res;
	}
	
	/**
	 * Hashes the concatenation of parameters using SHA-512 and returns resulting String 
	 * 
	 * @param msg
	 * 		body of the message we're going to hash
	 * @param type
	 * 		purpose of the hash (encrpytion or mac)
	 * 		
	 * @return result of the hash
	 */
	private String homeMadeHash(String msg, String type) {

		String algorithm = "SHA-512" ; // Algorithm chosen for digesting
		String data = msg + type;
		MessageDigest md = null ;
		try {
			md = MessageDigest.getInstance(algorithm) ; // MessageDigest instance instantiated with SHA-512 algorithm implementation
		} 
		catch( NoSuchAlgorithmException nsae) {
			System.out.println("No Such Algorithm Exception");
		}
		
		byte[] hash = null ;
		md.update(data.getBytes()) ; // Repeatedly use update method, to add all inputs to be hashed.
		hash = md.digest() ; // Perform actual hashing

		// convert bytes to bignum, then to hex string
        BigInteger big = new BigInteger(1, hash); 
        String hashString = big.toString(16); 
        while (hashString.length() < 32) {  // Ensure at least 32 
            hashString = "0" + hashString; 
        } 
        return hashString;
	}
	
	/**
	 * A method to decode encrypted messages from Alice 
	 */
	public String decrypt(String cipher) throws Exception {

		// Create cipher
		Cipher newCipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

		// use initialization vector with same block length
		byte[] base = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	    IvParameterSpec ivspec = new IvParameterSpec(base);
		
		// initialize cipher
		newCipher.init(Cipher.DECRYPT_MODE, decryptionKey, ivspec);
		
		// decrypt string 
		String res = "";
		try {
			byte[] decryptedBytes = newCipher.doFinal(decoder.decode(cipher));
			res = new String(decryptedBytes, "UTF-8");
		} catch (BadPaddingException e) {
			res = "Couldn't decrypt...I think the message was modified";
		}
		
		return res;
	}
	
	/**
	 * A method to check the mac tag on messages from Alice. 
	 * 
	 * Verifies the integrity of messages to ensure Mallory isn't disrupting communication 
	 */
	public Boolean macCheck(String message, String macString) throws Exception {

		// Create and initialize mac 
		Mac mac = Mac.getInstance("HmacSHA256");
		mac.init(macKey);

		// generate mac string 
		byte[] messageBytes = message.getBytes();
		byte[] macBytes = mac.doFinal(messageBytes);
		String newMacString = encoder.encodeToString(macBytes);

		// check that the mac strings are the same
		return macString.equals(newMacString);
	}

	private String processTransport(String trans) throws Exception {

		/* Break the message into 2 pieces */
		int index = trans.indexOf("\r\n")+2; 
		String signature = trans.substring(index); // Piece #1: B, tA, Enc(A,kAB; K_B)  
		String newTransport = trans.substring(0,index-2); // Piece #2: Sign(B, tA, Enc(A,kAB; K_B); k_A) 

		/*  Break B, tA, Enc(A,kAB; K_B) into its component parts */
		String[] transport = newTransport.split("\\n");

		/* Verify that transport message is recent */
		Date createdTime = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").parse(transport[1]);
		Date currentTime = new Date(System.currentTimeMillis());
		long convertedTime = ((currentTime.getTime() - createdTime.getTime()) / (1000 * 60)) % 60;
		if (transport[0].equals("Bob") || transport[0].equals("bob") ) {
			boolean isRecent = convertedTime < 2;
			if (isRecent && signature(newTransport, signature)) {
				return transportHelper(transport); 
			} else {
				return "Done"; // Fail if not recent or signature doesn't match 
			}
		} else {
			return "";
		}
	}
	
	private String transportHelper(String[] transport) throws Exception {

		// Create and initialize cipher 
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, bobPrivateKey);

		// Decode and save kAB
		String sharedKeyString = new String(cipher.doFinal(decoder.decode(transport[2])),"UTF-8");
		String[] splitSessionKey = sharedKeyString.split("\\n");
		String keyEncoded = splitSessionKey[1];
		byte[] decodedKey = decoder.decode(keyEncoded);
		SecretKeySpec sharedKeySpec = new SecretKeySpec(decodedKey, "AES");
		sharedKey = sharedKeySpec;

		// Use our hash function to generate decryption key  
		byte[] decryptionKeyHashBytes = decoder.decode(homeMadeHash(keyEncoded, "encrypt"));
		byte[] decryptionKeyBytes = Arrays.copyOfRange(decryptionKeyHashBytes, 0,32);
		SecretKeySpec decryptionKeySpec = new SecretKeySpec(decryptionKeyBytes, "AES");
		decryptionKey = decryptionKeySpec;

		// Use our hash function to generate mac verification key 
		byte[] macKeyHashBytes = decoder.decode(homeMadeHash(keyEncoded, "mac"));
		SecretKeySpec macKeySpec = new SecretKeySpec(macKeyHashBytes, "AES");
		macKey = macKeySpec;

		return "Key Received";
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
