import java.io.*;
import java.net.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.interfaces.RSAPublicKey;
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
	private RSAPublicKey alicePublicKey;
	private RSAPublicKey bobPublicKey;

	// Mallory's secret key for disrupting messages 
	private SecretKey malKey; 
	private SecretKey encryptionKey;
	private SecretKey macKey;
    
    //instance variables
    private boolean mac;
	private boolean enc;

    public Base64.Encoder encoder = Base64.getEncoder();
    public Base64.Decoder decoder = Base64.getDecoder();
	
	// Lists to keep track of previous messages 
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

		// Create an AES key for encryption and mac
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128, new SecureRandom());
		malKey = keyGen.generateKey();
		// Create encryption key
		byte[] encryptionKeyBytes = malKey.getEncoded();
		byte[] encryptionKeyShortBytes = Arrays.copyOfRange(encryptionKeyBytes, 0, 32);
		encryptionKey = new SecretKeySpec(encryptionKeyShortBytes, "AES");
		// Create mac key
		byte[] macKeyBytes = malKey.getEncoded();
		macKey = new SecretKeySpec(macKeyBytes, "AES");
		
		// Read in RSA keys 
		readKeys();

		// Initialize message history
		incomingMessages.add("No message history to replay");
		incomingMacs.add("No mac history to replay");
		
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
			
			// Read key transport 
			String keyTransportMessage = streamIn.readUTF();
			// Forward it to Bob
			streamOut.writeUTF(keyTransportMessage);
			// Save in message history 
            incomingMessages.add(keyTransportMessage);
            incomingMacs.add("");
            
            // STEP 3: RELAY MESSAGES FROM ALICE TO BOB
            boolean finished = false;
			while(!finished) {
				try {
					// Read message from Alice
					String incomingMsg = streamIn.readUTF();
					String macString = "";
					if(mac) {
						macString = incomingMsg;
						incomingMsg = streamIn.readUTF();
					}

					System.out.println("Recieved message -- " + incomingMsg);
					if(mac) {
						System.out.println("Received mac string -- " + macString);
					}
					incomingMessages.add(incomingMsg);
					incomingMacs.add(macString);
					System.out.println("Commands: \n    (1) pass message along to Bob, \n    (2) drop the message, \n    (3) edit the message \n    (4) replay old message");

					String line = console.nextLine();
					switch (line) {
						case "1":
							System.out.println("Passing message along to Bob");
							if(mac)
								streamOut.writeUTF(macString);
							streamOut.writeUTF(incomingMsg);
							streamOut.flush();
							break;
						case "2":
							System.out.println("Dropping message from Alice");
							break;
						case "3":
							System.out.print("Type a new message: ");
							String replacementMsg = console.nextLine();
							if (enc) {
								replacementMsg = encrypt(replacementMsg);
							} 
							if (mac) {
								streamOut.writeUTF(mac(replacementMsg));
							}
							streamOut.writeUTF(replacementMsg);
							streamOut.flush();		
							System.out.println("Sending new message instead...muahahaha");		
							break;
						case "4":
							if (mac) 
								streamOut.writeUTF(incomingMacs.get(incomingMacs.size() - 2));
							streamOut.writeUTF(incomingMessages.get(incomingMessages.size() - 2));
							streamOut.flush();
							System.out.println("Sending the prior message instead...muahahaha");
							break;	
						default: 
							System.out.println("Illegal argument! Passing the original message to Bob");
							streamOut.writeUTF(incomingMsg);
							streamOut.flush();
					}
					System.out.println("--------------------------------------------------");
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
		
			/* Read all Alice's public key bytes */
			Path path = Paths.get(ALICE_PUBLIC_KEY_PATH);
			byte[] bytes = Files.readAllBytes(path);

			/* Generate Alice's public key. */
			X509EncodedKeySpec ksA = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			alicePublicKey = (RSAPublicKey) kf.generatePublic(ksA);

			// --------------------------------------------------------------------------

			/* Read all Bob's public key bytes */
			path = Paths.get(BOB_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate Bob's public key. */
			X509EncodedKeySpec ksB = new X509EncodedKeySpec(bytes);
			bobPublicKey = (RSAPublicKey) kf.generatePublic(ksB);
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
