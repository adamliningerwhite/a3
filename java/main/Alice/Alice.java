import java.io.*;
import java.math.BigInteger;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.text.SimpleDateFormat;
import java.security.spec.*;

import java.time.LocalTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.*;

public class Alice {

	// Constants for RSA keys
	private static final String ALICE_PUBLIC_KEY_PATH = "alicePublic.key";
	private static final String ALICE_PRIVATE_KEY_PATH = "alicePrivate.key";
	private static final String BOB_PUBLIC_KEY_PATH = "bobPublic.key";
	private static final String PUBLIC_KEY_FORMAT = "X.509";
	private static final String PRIVATE_KEY_FORMAT = "PKCS#8";

	// Keys for encryption and integrity
	private SecretKey sharedKey;
	private SecretKey macKey;
	private SecretKey encryptionKey;
	
	// RSA keys 
	private RSAPrivateKey alicePrivateKey;
	private RSAPublicKey alicePublicKey;
	private RSAPublicKey bobPublicKey;

	// instance variables
	private boolean mac;
	private boolean enc;

	// Utilities
	public Base64.Encoder encoder = Base64.getEncoder();
	public Base64.Decoder decoder = Base64.getDecoder();

	public Alice(String malloryPort, String config) throws Exception {

		// Apply configuration
		if (config.compareTo("noCrypto") == 0) {
			mac = false;
			enc = false;
		} else if (config.compareTo("enc") == 0) {
			mac = false;
			enc = true;
		} else if (config.compareTo("mac") == 0) {
			mac = true;
			enc = false;
		} else if (config.compareTo("EncThenMac") == 0) {
			mac = true;
			enc = true;
		}

		// Read in RSA keys
		readKeys();
		
		Scanner console = new Scanner(System.in);
		System.out.println("This is Alice");

		// obtain server's port number and connect to it
		int serverPort = Integer.parseInt(malloryPort);
		String serverAddress = "localhost";

		try {
			// Connect to mallory server
			Socket serverSocket = new Socket(serverAddress, serverPort);
			System.out.println("Connected to Server Mallory");
			DataOutputStream streamOut = new DataOutputStream(serverSocket.getOutputStream());

			// Generate key transfer message to establish symmetric encryption scheme
			String keyTransferMessage = getKeyTransferMessage();
			// System.out.println(keyTransferMessage);

			// Send shared session key to Bob
			streamOut.writeUTF(keyTransferMessage);
			streamOut.flush();
			System.out.println("Shared key en route to Bob!");
			
			// --------------------------------------------------------------------------

			/**
			 * obtain the message from the user and send it to server 
			 * the communication ends when the user inputs "done"
			 */
			int counter = 0; 	// counter to track what message we're on
			String line = "";
			while (!line.equals("done")) {
				try {
					counter++; 	// increment message counter
					System.out.print("Type message: ");
					line = console.nextLine();

					// Package message and append message number
					// String packagedMsg = packageMessage(line + ": " + counter);
					String packagedMsg = packageMessage(line);

					if (enc) {
						packagedMsg = encrypt(packagedMsg);
					} 
					if (mac) {
						streamOut.writeUTF(mac(packagedMsg));
					}

					System.out.println(packagedMsg);
					streamOut.writeUTF(packagedMsg);
					streamOut.flush();
					System.out.println("Message en route to Bob");
				} catch (IOException ioe) {
					System.out.println("Sending error: " + ioe.getMessage());
				}
			}
			// close all the sockets and console
			console.close();
			streamOut.close();
			serverSocket.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	/**
	 * Method to encrypt messages using symmetric encryption scheme. 
	 * 
	 * @param str 
	 * 		The plaintext message that we want to encrypt
	 * 
	 * @return cipher text for str
	 */
	private String encrypt(String str) {
		String result = "";
		try {
			// create cipher
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

			// use initialization vector with same block length
			byte[] iv = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
			IvParameterSpec ivspec = new IvParameterSpec(iv);

			// initialize cipher 
			cipher.init(Cipher.ENCRYPT_MODE, encryptionKey, ivspec); 

			// encrypt string 
			byte[] strBytes = str.getBytes();
			byte[] encryptedBytes = cipher.doFinal(strBytes);
			String encryptedString = encoder.encodeToString(encryptedBytes);
			
			result = encryptedString;

		} catch (Exception e) {
			e.printStackTrace();
		}
		return result;
	}
 
	/**
	 * Method to generate mac tag using symmetric encryption scheme 
	 * 
	 * @param str 
	 * 		string for which we'll create a tag
	 * @return
	 * 		tag for message
	 */
	private String mac(String str) {
		String result = "";
    	try {
			// Create and initialize Mac generator 
			Mac mac = Mac.getInstance("HmacSHA256");
			mac.init(macKey);

			// Create tag
			byte[] strBytes = str.getBytes();
			byte[] macBytes = mac.doFinal(strBytes);
			String taggedString = encoder.encodeToString(macBytes);
			
			result = taggedString;
			
		} catch (Exception e) {
			e.printStackTrace();
		}
    	return result;
	}

	/**
	 * A method to generate the message that establishes a symmetric encryption scheme
	 * 
	 *  A -> B: B, tA, Enc(A,kAB; K_B), Sign(B, tA, Enc(A,kAB; K_B); k_A)
	 * 
	 * @return
	 * 		the string Alice sends to Bob containing the shared key for sym enc
	 */
	private String getKeyTransferMessage() {
		
		String transferMessage = ""; // message we build and return
		
		// basic pieces of message
		String A = "Alice";
		String B = "Bob";
		String tA = new SimpleDateFormat("yyyy.MM.dd.HH.mm.ss").format(new Date(System.currentTimeMillis()));

		try {
			
			// Generate shared key (kAB) 
			KeyGenerator keyGen = KeyGenerator.getInstance("AES");
			keyGen.init(128, new SecureRandom());
			sharedKey = keyGen.generateKey();

			// Get shared key (kAB) as string 
			String kAB = encoder.encodeToString(sharedKey.getEncoded());
			
			/* Hash the shared key to produce a key specifically for encryption */
			String encyrptKeyHashString = homeMadeHash(kAB, "encrypt");
			byte[] encryptKeyBytes = decoder.decode(encyrptKeyHashString);
			byte[] encrpytKey = Arrays.copyOfRange(encryptKeyBytes, 0, 32); // only want first 32 bits
			encryptionKey = new SecretKeySpec(encrpytKey, "AES");

			/* Repeat this process to produce a key for mac */
			String macKeyHashString = homeMadeHash(kAB, "mac");
			byte[] macKeyBytes = decoder.decode(macKeyHashString);
			byte[] macKey = Arrays.copyOfRange(macKeyBytes, 0, 32);
			this.macKey = new SecretKeySpec(macKey, "AES");

			/* Build Enc(A, kAB; K_B) piece of message */
			String toEncryptString = A + "\n" + kAB;
			byte[] toEncryptBytes = toEncryptString.getBytes();
			Cipher cipher = Cipher.getInstance("RSA");
			cipher.init(Cipher.ENCRYPT_MODE, bobPublicKey, new SecureRandom());
			byte[] encryptedBytes = cipher.doFinal(toEncryptBytes);	
			String encryptedString = encoder.encodeToString(encryptedBytes);		

			/* Build Sign(B, tA, Enc(A,kAB; K_B); k_A) piece of message */
			String toSignString = B + "\n" + tA + "\n" + encryptedString;
			byte[] toSignBytes = toSignString.getBytes();
			Signature signature = Signature.getInstance("SHA256withRSA");
			signature.initSign(alicePrivateKey);
			signature.update(toSignBytes);
			byte[] signedBytes = signature.sign();
			String signedString = encoder.encodeToString(signedBytes);

			transferMessage = B + "\n" + tA + "\n" + encryptedString + "\n"  + signedString;
		}
		catch (Exception e) {
			e.printStackTrace();
		}
		return transferMessage;
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
	 * Read relevant keys from files and save them in instance variables
	 * 
	 * For alice, we read: 
	 * 		1. Her private RSA key 
	 * 		2. Her public RSA key 
	 * 		3. Bob's public RSA key
	 * 
	 */
	private void readKeys() {
		try {
			/* Read all bytes from Alice's private key file */
			Path path = Paths.get(ALICE_PRIVATE_KEY_PATH);
			byte[] bytes = Files.readAllBytes(path);

			/* Generate Alice's private key. */
			PKCS8EncodedKeySpec ks1 = new PKCS8EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			alicePrivateKey = (RSAPrivateKey) kf.generatePrivate(ks1);

			// --------------------------------------------------------------------------

			/* Read all Alice's public key bytes */
			path = Paths.get(ALICE_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate Alice's public key. */
			X509EncodedKeySpec ks2 = new X509EncodedKeySpec(bytes);
			alicePublicKey = (RSAPublicKey) kf.generatePublic(ks2);

			// --------------------------------------------------------------------------

			/* Read all Bob's public key bytes */
			path = Paths.get(BOB_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate Bob's public key. */
			X509EncodedKeySpec ks3 = new X509EncodedKeySpec(bytes);
			bobPublicKey = (RSAPublicKey) kf.generatePublic(ks3);

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

	private String packageMessage(String message) throws Exception {
		StringBuilder acc = new StringBuilder();
		acc.append(message);
		
		return acc.toString();
    }
    
    /**
     * args[0] ; port that Alice will connect to (Mallory's port)
     * args[1] ; program configuration
     */
    public static void main(String[] args) {
	
		//check for correct # of parameters
		if (args.length != 2) {
			System.out.println("Incorrect number of parameters");
		} else {
			//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
			//create Alice to start communication
			try {
				Alice alice = new Alice(args[0], args[1]);
			} 
			catch (Exception e) {
				e.printStackTrace();
			}
		}
	
    }
}
