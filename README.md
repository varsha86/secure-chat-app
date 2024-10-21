Secure Chat Application

Project Description

This project is a secure chat application that ensures "end-to-end encryption" of communication between users. It implements "Elliptic Curve Diffie-Hellman (ECDH)" for key exchange, "AES" for message encryption, "HMAC" for message authentication, and includes a simple "user authentication" system to verify users before exchanging messages.

The chat system ensures that no one except the intended recipient can read the message, even if the message is intercepted during transmission.

Features

Secure Key Exchange: Using Elliptic Curve Diffie-Hellman (ECDH), a symmetric key is derived between the client and server for encrypted communication.

Message Encryption: AES (Advanced Encryption Standard) is used to encrypt and decrypt messages, ensuring confidentiality.

Message Authentication (HMAC): A Hash-based Message Authentication Code (HMAC) is appended to each message to ensure message integrity and protect against tampering.

User Authentication: A basic username-password authentication system is implemented. Passwords are hashed using "PBKDF2" to provide protection against brute force attacks.

Session Management: Each client has a unique session with a derived symmetric key, allowing multiple clients to connect to the server securely.

Multi-client Support: The server can handle multiple clients, allowing for real-time communication between connected users.

Technologies Used

Python
Socket Programming for communication between client and server
Elliptic Curve Cryptography (ECC) for key exchange
AES (Advanced Encryption Standard) for encryption
HMAC (Hash-based Message Authentication Code) for integrity checks
PBKDF2 (Password-Based Key Derivation Function 2) for password hashing
Threading to support multiple clients on the server
Prerequisites

Ensure you have Python 3.x installed along with the following Python libraries:

cryptography
To install the required library:

pip install cryptography
How to Run the Application

Clone the Repository
git clone https://github.com/your-repo/secure-chat-app.git
cd secure-chat-app
Start the Server

Navigate to the project directory.

Run the server.py script to start the server.

python server.py
The server will be listening on localhost port 9999.

Start the Client(s)

Open another terminal window.

Run the client.py script to start the client.

python client.py
Each client will:

Prompt for a username and password for authentication.
Exchange public keys with the server to derive a shared secret.
Securely send and receive encrypted messages.
Chatting
After successful connection and authentication, users can send messages to the server.
Messages will be encrypted using AES, authenticated with HMAC, and then sent to the server.
The server will broadcast the message to all connected clients, excluding the sender.
Exiting the Chat
To exit the chat, type exit and press Enter.
Folder Structure

secure-chat-app/
│
├── client.py           # Client-side implementation
├── server.py           # Server-side implementation
└── README.md           # Project documentation
Code Overview

server.py

The server generates an EC key pair and waits for clients to connect.
Upon client connection, the server:
Authenticates the client using a simple username-password mechanism.
Sends its public key to the client for key exchange.
Receives the client's public key and derives a symmetric AES key.
Listens for encrypted messages from the client, verifies HMAC integrity, and decrypts the message.
Broadcasts the message to all connected clients.
client.py

The client:
Connects to the server and performs authentication by sending a hashed password.
Exchanges public keys with the server to derive a shared symmetric key.
Encrypts messages using AES and sends them to the server.
Verifies the HMAC of incoming messages to ensure integrity.
Security Considerations

Elliptic Curve Cryptography ensures secure key exchanges with high efficiency.
AES-256 ensures that messages are securely encrypted.
HMAC guarantees message integrity, ensuring that messages are not tampered with during transmission.
PBKDF2 securely hashes passwords, making it harder for attackers to break them using brute-force or dictionary attacks.
