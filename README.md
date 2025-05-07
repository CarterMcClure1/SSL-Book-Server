This project is a C-based socket programming system that allows multiple clients to interact with a central book management server over an encrypted SSL/TLS connection. It features:

✅ Secure user login with password hashing (SHA-256)

🔐 Encrypted communication using OpenSSL

📚 Book search & management (e.g., borrow, return, availability check)

🧠 User recommendations based on search and borrow history

🧵 Multi-client support via fork()

🔧 Developed using low-level POSIX sockets and OpenSSL


This is runnable in linux. There are three steps to this
-If you included the makefile, you can type the "make" to compile this program. 

-Generate the .key and .crt files for SSL context. Run "openssl req -x509 -newkey rsa:2048 -keyout p3server.key -out p3server.crt -days 365 -nodes -subj "/CN=localhost""

Then run "./server server.conf" on one linux terminal and "./client client.conf" on another. 

Then use HELP to see available commands.
