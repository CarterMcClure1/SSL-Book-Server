This project is a C-based socket programming system that allows multiple clients to interact with a central book management server over an encrypted SSL/TLS connection. It features:

✅ Secure user login with password hashing (SHA-256)

🔐 Encrypted communication using OpenSSL

📚 Book search & management (e.g., borrow, return, availability check)

🧠 User recommendations based on search and borrow history

🧵 Multi-client support via fork()

🔧 Developed using low-level POSIX sockets and OpenSSL


This is runnable in linux. If you included the makefile, you can type the "make" to compile this program. Then run ./server server.conf on one linux terminal and ./client client.conf on another. 
