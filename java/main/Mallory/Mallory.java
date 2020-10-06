import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;
import java.text.SimpleDateFormat;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;

public class Mallory {

	// Constants for RSA keys
	private static String ALICE_PUBLIC_KEY_PATH = "alicePublic.key";
	private static String BOB_PUBLIC_KEY_PATH = "bobPublic.key";
	private static String PUBLIC_KEY_FORMAT = "X.509";

	//RSA keys 
	private PublicKey alicePublicKey;
	private PublicKey bobPublicKey;
    
    //instance variables
    private boolean mac;
	private boolean enc;

    public Base64.Encoder encoder = Base64.getEncoder();
    public Base64.Decoder decoder = Base64.getDecoder();
    
    ArrayList<String> incomingMessages = new ArrayList<String>();
    ArrayList<String> incomingMacs = new ArrayList<String>();
    
    public Mallory(String malloryPort, String bobPort, String config) throws Exception {

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

		// Check that keys are read correctly 
		// System.out.println("Alice's Public Key: " + keyToString(alicePublicKey));
		// System.out.println("--------------------------------------------------------");
		// System.out.println("Bob's Public Key: " + keyToString(bobPublicKey));
		
		System.out.println("This is Mallory");
		Scanner console = new Scanner(System.in);

        int myPortNumber = Integer.parseInt(malloryPort); // port to listen on 
        int bobPortNumber = Integer.parseInt(bobPort); // port to connect to 
        String serverAddress = "localhost";
	
        try {
			// STEP 1: CONNECT TO BOB SERVER TO SEND MESSAGES
			Socket serverSocket = new Socket(serverAddress, bobPortNumber);
			System.out.println("Connected to Server Bob");
			DataOutputStream streamOut = new DataOutputStream(serverSocket.getOutputStream());
			
            // STEP 2: CREATE A SERVER TO RECIEVE MESSAGES FROM ALICE
			ServerSocket malloryServer = new ServerSocket(myPortNumber);
            System.out.println("Mallory Server started at port "+myPortNumber);
			Socket clientSocket = malloryServer.accept();	// accept the client (a.k.a. Mallory)
			System.out.println("Alice connected");
            DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            
            String key = streamIn.readUTF();
            incomingMessages.add(key);
            incomingMacs.add("");
            
            // STEP 3: RELAY MESSAGES FROM ALICE TO BOB
            boolean finished = false;
			while(!finished) {
				try {
					// Read message from Alice
					String incomingMsg = streamIn.readUTF();
					String macString = "";
					if(mac) {
						macString = streamIn.readUTF();
					}
					//history.add(new Pair<incoming>)

					System.out.println("Recieved message -- " + incomingMsg + " -- from Alice");
					if(mac) {
						System.out.println("Received mac string -- " + macString + " -- from Alice");
					}
					System.out.println("Commands: (1) pass message along to Bob, (2) drop the message, or (3) modify the message (send 2 copies)");

					String line = console.nextLine();
					switch (line) {
						case "1":
							System.out.println("Passing message along to Bob");
							streamOut.writeUTF(incomingMsg);
							if(mac)
								streamOut.writeUTF(macString);
							streamOut.flush();
							break;
						case "2":
							System.out.println("Dropping message from Alice");
							break;
						case "3":
							System.out.println("Write new message: ");
							incomingMsg = console.nextLine();
							packageMessage(streamOut, incomingMsg, macString);
							streamOut.flush();					
							break;
						default: 
							System.out.println("Illegal argument! Passing the original message to Bob");
							streamOut.writeUTF(incomingMsg);
							streamOut.flush();
					}
                    finished = incomingMsg.equals("done");
				}
				catch(IOException ioe) {
					//disconnect if there is an error reading the input
					finished = true;
				}
			}
			//clean up the connections before closing
			malloryServer.close();
			streamIn.close();
			//close all the sockets and console 
			streamOut.close();
			serverSocket.close();
			System.out.println("Mallory closed");
        }
        catch (IOException e) {
            System.out.println("Error in creating this server or connecting to other server");
            System.out.println(e.getMessage());
		}
	}	
		
	private void readKeys() {
		try  {
			// GENERATE BOB'S PUBLIC KEY
			/* Read all the public key bytes */
			Path path = Paths.get(BOB_PUBLIC_KEY_PATH);
			byte[] bytes = Files.readAllBytes(path);

			/* Generate public key. */
			X509EncodedKeySpec ks1 = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			bobPublicKey = kf.generatePublic(ks1);

			// GENERATE ALICE'S PUBLIC KEY
			/* Read all the public key bytes */
			path = Paths.get(ALICE_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate public key. */
			X509EncodedKeySpec ks2 = new X509EncodedKeySpec(bytes);
			alicePublicKey = kf.generatePublic(ks2);
		}
		catch (Exception e) {
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
			cipher.init(Cipher.ENCRYPT_MODE, bobPublicKey, ivspec); 

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
	
	
	private void packageMessage(DataOutputStream streamOut, String message, String macKey) throws IOException {
		String newMessage = message;
		String newMac = macKey;

		if (enc) {
			newMessage = encrypt(newMessage);
		}
		streamOut.writeUTF(newMessage);
		if (mac) {
			newMac = mac(newMessage);
			streamOut.writeUTF(newMac);
		} 
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
			mac.init(bobPublicKey);

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
     * args[0] ; port Mallory will connect to (Bob's port)
	 * args[1] ; port where Mallory expects connection (from Alice)
     * args[2] ; program configuration
     */
    public static void main(String[] args) {
		//check for correct # of parameters
		if (args.length != 3) {
			System.out.println("Incorrect number of parameters");
			return;
		}
		//Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		
		//create Mallory
		try {
			Mallory mal = new Mallory(args[1], args[0], args[2]);
		} 
		catch (Exception e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}		
    }
}
