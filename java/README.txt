Project by Jack Bernstein & Adam Lininger-White

To run this code:

1. Compile the java code
   > javac main/Alice.java
   > javac main/Bob.java

2. Run the server: java main/Bob <port> <config>
   > java main/Bob 8047 noCrypto

3. Run the client: java main/Alice <server_port> <config>
   > java main/Alice 8047 noCrypto
