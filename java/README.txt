Project by Jack Bernstein & Adam Lininger-White

Note to Jack

Key Transfer Protocol Message: 

All sent as one message with different pieces separated by newline characters
B
tA
Enc(A, kAB; K_B)
Sign(B, tA, Enc(A, kAB; K_B); k_A)

Alice's normal messages take the following form:
   Case 1: "noCrypto" 
      plain text 
   Case 2: "enc"
      cipher text 
   Case 3: "mac"
      plain text + "\n" + mac(plain text)
   Case 4: "EncThenMac" 
      cypher text + "\n" + mac(cypher text)
      
   * Everything is sent as one message, with newlines separating the possible pieces

----------------------------------------------------------

To run this code:

1. Compile the java code
   > javac main/Alice.java
   > javac main/Bob.java

2. Run the server: java main/Bob <port> <config>
   > java main/Bob 8047 noCrypto

3. Run the client: java main/Alice <server_port> <config>
   > java main/Alice 8047 noCrypto
   

