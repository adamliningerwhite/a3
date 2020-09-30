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

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;

public class Mallory {

	// Constants for RSA keys
	private static String ALICE_PUBLIC_KEY_PATH = "alicePublic.pub";
	private static String BOB_PUBLIC_KEY_PATH = "bobPublic.pub";
	private static String PUBLIC_KEY_FORMAT = "X.509";

	//RSA keys 
	private PublicKey alicePublicKey;
	private PublicKey bobPublicKey;
    
    //instance variables
    private boolean mac;
	private boolean enc;
	
	ArrayList<String> history = new ArrayList<String>();

    public Base64.Encoder encoder = Base64.getEncoder();
    public Base64.Decoder decoder = Base64.getDecoder();
    
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
            // accept the client(a.k.a. Mallory)
			Socket clientSocket = malloryServer.accept();
			System.out.println("Alice connected");
            DataInputStream streamIn = new DataInputStream(new BufferedInputStream(clientSocket.getInputStream()));
            
            // STEP 3: RELAY MESSAGES FROM ALICE TO BOB
            boolean finished = false;
			while(!finished) {
				try {
					// Read message from Alice
					String incomingMsg = streamIn.readUTF();
					// Split it into the message body and message number 
					String[] pieces = incomingMsg.split(":");
					String msg = pieces[0];
					String msgNum = pieces[1];
					String packagedMsg = packageMessage(incomingMsg);

					// Save this message 
					// TODO: Determine which msg to save, body or whole thing
					history.add(incomingMsg);

					System.out.println("Recieved message -- " + msg + " -- from Alice");
					System.out.println("Commands: (1) pass message along to Bob, (2) drop the message, or (3) modify the message (send 2 copies)");

					String line = console.nextLine();
					switch (line) {
						case "1":
							System.out.println("Passing message along to Bob");
							// Pass message along to Bob
							streamOut.writeUTF(packagedMsg);
							streamOut.flush();
							break;
						case "2":
							System.out.println("Dropping message from Alice");
							break;
						case "3":
							System.out.println("Message modified, sending two copies instead!"); 
							streamOut.writeUTF(packagedMsg + packagedMsg);
							streamOut.flush();					
							break;
						default: 
							System.out.println("Defaulting to passing the original message to Bob");
							streamOut.writeUTF(packagedMsg);
							streamOut.flush();
					}
                    finished = msg.equals("done");
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
			X509EncodedKeySpec ks = new X509EncodedKeySpec(bytes);
			KeyFactory kf = KeyFactory.getInstance("RSA");
			bobPublicKey = kf.generatePublic(ks);

			// GENERATE ALICE'S PUBLIC KEY
			/* Read all the public key bytes */
			path = Paths.get(BOB_PUBLIC_KEY_PATH);
			bytes = Files.readAllBytes(path);

			/* Generate public key. */
			ks = new X509EncodedKeySpec(bytes);
			bobPublicKey = kf.generatePublic(ks);
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
