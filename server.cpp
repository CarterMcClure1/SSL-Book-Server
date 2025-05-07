#include <iostream>
#include <string>
#include <cstring>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/wait.h>
#include <cerrno>
#include <system_error>
#include <fstream>
#include <algorithm>
#include <vector>
#include <set>
#include <ctime>
#include <map>
#include "bookmanager.cpp"
#include <unistd.h>
#include <sstream>
#include <mutex>
#include <sys/sysinfo.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <fcntl.h>


#define BACKLOG 10
#define MAXDATASIZE 100


void sigchld_handler(int s)
{
    (void)s;

    int saved_errno = errno;

    while(waitpid(-1, NULL, WNOHANG) > 0);

    errno = saved_errno;
}
 


void* get_in_addr(struct sockaddr* sa)
{
    if (sa->sa_family == AF_INET)
    {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}





std::string toCamelCase(const std::string& input)
{
    std::string output;
    bool capitalize = true;

    for (char c : input) {
        if (std::isalpha(c)) {
            if (capitalize) {
                output += std::toupper(c);
            } else {
                output += std::tolower(c);
            }
            capitalize = !capitalize;
        } else {
            output += c;
        }
    }
    return output;
}

void logConnection(const std::string& clientIP)
{
    time_t now = time(nullptr); 
    tm* localTime = localtime(&now); 
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
    std::cout << "[" << timestamp << "] Connection from: " << clientIP << std::endl;
}

void logDisconnection(const std::string& clientIP)
{
    time_t now = time(nullptr);  
    tm* localTime = localtime(&now); 
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);
    std::cout << "[" << timestamp << "] Client disconnected: " << clientIP << std::endl;
}



SSL_CTX *create_myserver_context() {
    SSL_CTX *ctx;

    // Use the TLS server method
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set protocol version
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);
        

    // Load server certificate and private key
    SSL_CTX_use_certificate_file(ctx, "p3server.crt", SSL_FILETYPE_PEM);
        

    SSL_CTX_use_PrivateKey_file(ctx, "p3server.key", SSL_FILETYPE_PEM);
        

    // Verify private key
    if (!SSL_CTX_check_private_key(ctx)) {
        fprintf(stderr, "Private key does not match the public certificate\n");
        exit(EXIT_FAILURE);
    }

    return ctx;
}

std::string generateRandomPassword() {
    std::string password;
    password.clear();
    const char *acceptedCharacters = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
    const char *acceptedSymbols = "!@#$%&*";
    unsigned char buffer[5];

    RAND_bytes(buffer, sizeof(buffer));

    for(int i = 0; i < 5; ++i) {
        if(i == 0) {
            password += acceptedCharacters[buffer[i] % 62];  //make sure first letter is alphanum
        }
        else if(buffer[i] % 5 == 3) {
            password += acceptedSymbols[buffer[i] % 7];  //1 in 5 chance of generating symbol, otherwise add another alphanum
        }
        else {
            password += acceptedCharacters[buffer[i] % 62];
         }
    }

    return password;

    //STILL NEED PASSWORD STRENGTH CHECKER/MAKE SURE ONE UPPERCASE/ONE SYMBOL/ONE NUMBER
}
 
bool checkPasswordStrength(std::string password) {
    bool hasUppercaseLetter = false;
    bool hasNumber = false;
    bool hasSymbol = false;

    const char *acceptedSymbols = "!@#$%&*";

    for(int i = 0; i < password.length(); ++i) {
        if(std::isupper(password[i])) {
            hasUppercaseLetter = true;
        }
        if(std::isdigit(password[i])) {
            hasNumber = true;
        }
        if(strchr(acceptedSymbols, password[i])) {
            hasSymbol= true;
        }
    }

    if(hasUppercaseLetter && hasNumber && hasSymbol) {
        return true;
    }
    else {
        return false;
    }
}

std::string generateRandomSalt() {
    std::string salt;
   const char *acceptedCharacters = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
   unsigned char buffer[6];

   RAND_bytes(buffer, sizeof(buffer));

   for (int i = 0; i < 6; ++i) {
        salt += acceptedCharacters[buffer[i] % 62];
    }

    return salt;
}

std::string saltPassword(std::string pass, std::string salt) {
    std::string saltedPassword;
    
    for (int i = 0; i < 6; ++i) {
        if (i < salt.length()) { 
            saltedPassword += salt[i]; }

        if (i < pass.length()) {
            saltedPassword += pass[i]; }
    }

    return saltedPassword;
}

std::vector<unsigned char> generateRandomInitialVector() {
    std::vector<unsigned char> initialVec(16);
    RAND_bytes(initialVec.data(), 16);
    return initialVec;
}

std::vector<unsigned char> encryptMyPassword(std::string pass, std::vector<unsigned char> initialVector) {
    std::vector<unsigned char> password(pass.begin(), pass.end());
    std::vector<unsigned char> encryptedPassword(password.size() + EVP_MAX_BLOCK_LENGTH);
    std::string preSharedKey = "F24447TG";
    std::vector<unsigned char> key(16, 0); 
    std::copy(preSharedKey.begin(), preSharedKey.end(), key.begin());
    int lengthUpdate = 0;
    int lengthFinal = 0;


    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), initialVector.data());
    EVP_EncryptUpdate(ctx, encryptedPassword.data(), &lengthUpdate, password.data(), password.size());
    EVP_EncryptFinal_ex(ctx, encryptedPassword.data() + lengthUpdate, &lengthFinal);

    encryptedPassword.resize(lengthUpdate + lengthFinal);

    EVP_CIPHER_CTX_free(ctx);

    return encryptedPassword;


}

std::string decryptMyPassword(std::vector<unsigned char> encryptedPass, std::vector<unsigned char> initialVector) {
    std::vector<unsigned char> decryptedPassword(encryptedPass.size());
    std::string preSharedKey = "F24447TG";
    std::vector<unsigned char> key(16, 0); 
    std::copy(preSharedKey.begin(), preSharedKey.end(), key.begin());
    int lengthUpdate= 0;
    int lengthFinal = 0;


    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key.data(), initialVector.data());
    EVP_DecryptUpdate(ctx, decryptedPassword.data(), &lengthUpdate, encryptedPass.data(), encryptedPass.size());
    
    lengthFinal = lengthUpdate;

    EVP_DecryptFinal_ex(ctx, decryptedPassword.data() + lengthFinal, &lengthUpdate);
    lengthFinal = lengthFinal + lengthUpdate;

    decryptedPassword.resize(lengthFinal);

    EVP_CIPHER_CTX_free(ctx);

    std::string encryptedPasswordString(decryptedPassword.begin(), decryptedPassword.end());
    
    return encryptedPasswordString;
    
    
}

std::string bytesToHex(unsigned char* bytes, int length) {
    static const char hexDigits[] = "0123456789abcdef";
    std::string hexString;
    hexString.reserve(length *2);

    for (int i = 0; i < length; ++i) {
        hexString.push_back(hexDigits[bytes[i] >> 4]); 
        hexString.push_back(hexDigits[bytes[i] & 0x0F]); 
    }

    return hexString;
}

std::string hashTheSaltedPassword(const std::string& saltedPass) {
    
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    

    
    const EVP_MD* messageDigest = EVP_sha512();

    
   unsigned char hash[EVP_MAX_MD_SIZE];
   unsigned int hashLength;

    
    EVP_DigestInit_ex(ctx, messageDigest, nullptr);
    EVP_DigestUpdate(ctx, saltedPass.c_str(), saltedPass.length()); 
    EVP_DigestFinal_ex(ctx, hash, &hashLength);
        
    
    EVP_MD_CTX_free(ctx);

    
    return bytesToHex(hash, hashLength);
}


void writeToSecretFile(std::string username, std::string salt, std::string hashedSaltedPassword) {
    std::ofstream hiddenfile(".book_shadow", std::ios::app);
    if (!hiddenfile) {
        std::cerr << "Failed to open .book_shadow file" << std::endl;
        return;
    }
    hiddenfile << username << ":" << salt << ":" << hashedSaltedPassword << std::endl;
    hiddenfile.close();

}

bool isUsernameTaken(std::string username) {
    std::ifstream readHiddenFile(".book_shadow");
    if (!readHiddenFile) {
        std::cerr << "Failed to open .book_shadow file" << std::endl;
        return false; 
    }

    std::string line;
    while (std::getline(readHiddenFile, line)) {
        std::istringstream stream(line);
        std::string storedUsername;
        if (std::getline(stream, storedUsername, ':')) {
            if (storedUsername == username) {
                return true; 
            }
        }
    }

    return false; // Username not found
}

std::string getSaltFromFile(std::string username) {
    std::string salt;
    std::ifstream readHiddenFile(".book_shadow");
    if (!readHiddenFile) {
        std::cerr << "Failed to open .book_shadow file" << std::endl;
       
    }

    std::string line;
    while (std::getline(readHiddenFile, line)) {
        std::istringstream stream(line);
        std::string storedUsername, salt, saltedPassword;

        // Extract the three fields separated by ':'
        if (std::getline(stream, storedUsername, ':') &&
            std::getline(stream, salt, ':') &&
            std::getline(stream, saltedPassword)) {
            if (storedUsername == username) {
                return salt; // Return the salt if username matches
            }
        }
    }

    return "User not found"; // Username not found
}

std::string getHashFromFile(std::string username) {
    std::string salt;
    std::ifstream readHiddenFile(".book_shadow");
    if (!readHiddenFile) {
        std::cerr << "Failed to open .book_shadow file" << std::endl;
       
    }

    std::string line;
    while (std::getline(readHiddenFile, line)) {
        std::istringstream stream(line);
        std::string storedUsername, salt, saltedPassword;

        // Extract the three fields separated by ':'
        if (std::getline(stream, storedUsername, ':') &&
            std::getline(stream, salt, ':') &&
            std::getline(stream, saltedPassword)) {
            if (storedUsername == username) {
                return saltedPassword; // Return the salt if username matches
            }
        }
    }

    return "User not found"; // Username not found
}
 


int main(int argc, char* argv[])
{
   int sockfd, new_fd;
    SSL_CTX *ctx = create_myserver_context();
    struct addrinfo hints, *servinfo, *p;
    struct sockaddr_storage their_addr;
    socklen_t sin_size;
    struct sigaction sa;
    int yes = 1;
    char s[INET6_ADDRSTRLEN];
    int rv;

    fd_set socket_list, temp_socket_list; 
    int maxsocknum; 

    

    char hostname[256];
    gethostname(hostname, sizeof(hostname));
    BookManager bookManager;
    std::vector<Book> books = bookManager.loadBooksFromFile("books.db");
    ClientManager clientManager;

    std::memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE;

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <config_file>" << std::endl;
        return 1;
    }

   std::string configFileName = argv[1];

    std::string port;
    std::ifstream configFile(configFileName);
    if (!configFile.is_open()) {
        std::cerr << "Error opening configuration file: " << configFileName << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.substr(0, 5) == "PORT=") {
            port = line.substr(5);
            break;
        }
    }
    configFile.close();
    
    port.erase(0, port.find_first_not_of(" \t\n\r"));
    port.erase(port.find_last_not_of(" \t\n\r") + 1);
  


    if (port.empty()) {
        std::cerr << "Port number not found in configuration file!" << std::endl;
        return 1;
    }

    if ((rv = getaddrinfo(nullptr, port.c_str(), &hints, &servinfo)) != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    for (p = servinfo; p != nullptr; p = p->ai_next) {
        if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            std::perror("server: socket");
            continue;
        }

        if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            throw std::system_error(errno, std::generic_category(), "setsockopt");
        }

        if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            close(sockfd);
            std::perror("server: bind");
            continue;
        }

        break;
    }

    freeaddrinfo(servinfo);

    if (p == nullptr) {
        std::cerr << "server: failed to bind" << std::endl;
        return 1;
    }

    if (listen(sockfd, BACKLOG) == -1) {
        throw std::system_error(errno, std::generic_category(), "listen");
    }

    sa.sa_handler = sigchld_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = SA_RESTART;
    if (sigaction(SIGCHLD, &sa, nullptr) == -1) {
        throw std::system_error(errno, std::generic_category(), "sigaction");
    }



// Clear socket/temp socket list and add listening socket to socket list, initialize max socket number
    FD_ZERO(&socket_list); 
    FD_ZERO(&temp_socket_list);
    FD_SET(sockfd, &socket_list); 
    maxsocknum = sockfd; 

    std::cout << "server: waiting for connections..." << std::endl;

    // Get the current time at the start
   // clock_t lastHeartbeat = clock();
    //const double heartbeatIntervalInSeconds = static_cast<double>(heartbeatIntervalTimer) / CLOCKS_PER_SEC;

    fcntl(sockfd, F_SETFL, O_NONBLOCK);

    while (true) {
         temp_socket_list = socket_list; // COPY SOCKET LIST TO TEMP LIST

        //SELECT() to make sure multiplexing is going, allows mult. clients to interact
        if (select(maxsocknum + 1, &temp_socket_list, nullptr, nullptr, nullptr) == -1) {
            perror("select");
            exit(4);
        }


        // For loop to continously look for data incoming from clients
        for (int sock = 0; sock <= maxsocknum; sock++) {
            //this if handles new connections and calls accept()
            if (FD_ISSET(sock, &temp_socket_list)) { 
                if (sock == sockfd) {
                    
                    sin_size = sizeof their_addr;
                    new_fd = accept(sockfd, (struct sockaddr*)&their_addr, &sin_size);
                    if (new_fd == -1) {
                        perror("accept");
                        continue;
                    }
                    //fcntl(new_fd, F_SETFL, O_NONBLOCK);

                    inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
                    logConnection(s);

                    SSL *ssl = SSL_new(ctx);
                    SSL_set_fd(ssl, new_fd);
                    const char reply[] = "Connection is now ready!";

                    if (SSL_accept(ssl) <= 0) {
                    ERR_print_errors_fp(stderr);
                    SSL_free(ssl);
                    close(new_fd);
                    continue;
                     }
                     else {
                        SSL_write(ssl, reply, strlen(reply));
                     } 

                    // Add the new client socket to the socket list and update max sock number
                    FD_SET(new_fd, &socket_list);
                    if (new_fd > maxsocknum) { 
                        maxsocknum = new_fd;
                    }

                    clientManager.addClient(new_fd);
                    clientManager.addSSL(new_fd, ssl);
                    
                    
                    
                    

                } else {
                    // This else handles incoming data from client, call recv function
                    char buf[MAXDATASIZE];
                     
                    int numbytes;

                    int flags = fcntl(sock, F_GETFL, 0);
                    fcntl(sock, F_SETFL, flags | O_NONBLOCK);

                    SSL *ssl = clientManager.getSSL(sock);
                    
                    
                    if ((numbytes = SSL_read(ssl, buf, sizeof buf)) <= 0) {    //if recv gets nothing, close connection
                        
                        if (numbytes == 0) {
                            inet_ntop(their_addr.ss_family, get_in_addr((struct sockaddr*)&their_addr), s, sizeof s);
                            logDisconnection(s);
                        } else {
                            perror("recv");
                        }
                        close(sock); // Close the socket
                        FD_CLR(sock, &socket_list); // Remove from socket list
                        SSL_free(ssl);
                         // Remove from client manager(ADD THIS)
                    } else {                                                        //if recv gets data, start looking for commands entered                                        
                        
                        buf[numbytes] = '\0';
                        std::string receivedMsg(buf);
                        std::string camelCaseMsg = toCamelCase(receivedMsg);
                        

                    
                     std::string prefix = std::string(hostname) + ": ";



                     if (receivedMsg == "BYE") {                                            //HANDLES BYE, CAN BE DONE ANYTIME
                    std::string serverResponse = "200 Goodbye!";
                    SSL *ssl = clientManager.getSSL(sock); 
                    SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                    close(sock);
                    FD_CLR(sock, &socket_list);
                   SSL_free(ssl);
                }

            






           if(receivedMsg.find("USER") == 0) {
                            SSL *ssl = clientManager.getSSL(sock);
                            std::string serverResponse;
                            if(receivedMsg != "USER" && receivedMsg != "USER ")  {
                                std::string username = receivedMsg.substr(5);

                                //check if username is already registered
                                //if so prompt for password, received encrypted pass, decrypt it, salt it with saved salt, generate hash and compare
                                if(isUsernameTaken(username)) {
                                    std::string serverResponse = "Please enter password using PASS <password> command";
                                    SSL_write(ssl, serverResponse.c_str(), serverResponse.size());
                                    clientManager.enterPassMode(sock);
                                    clientManager.setTempUsername(sock, username);
                                }

                                else {
                            std::string serverResponse = "User " + username + " does not exist, creating User and returning password";
                            
                            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 

                            std::string newpass = generateRandomPassword();
                            while(!checkPasswordStrength(newpass)) {
                                newpass = generateRandomPassword();
                            }
                            std::string newsalt = generateRandomSalt();
                            std::string newsalted = saltPassword(newpass, newsalt);
                            std::string newhash = hashTheSaltedPassword(newsalted);

                            writeToSecretFile(username, newsalt, newhash);

                            std::vector<unsigned char> iv = generateRandomInitialVector();  
                            std::vector<unsigned char> encryptedPassword = encryptMyPassword(newpass, iv);
        
                            std::string marker = "@";
                            std::string ivString(iv.begin(), iv.end());
                            std::string encryptedString(encryptedPassword.begin(), encryptedPassword.end());
                            std::string markedData = marker + ivString + encryptedString;
                            std::string sizeString = std::to_string(encryptedPassword.size());
                            
                            SSL_write(ssl, markedData.c_str(), markedData.size());

                            SSL *ssl = clientManager.getSSL(sock); 
                            close(sock);
                            FD_CLR(sock, &socket_list);
                            SSL_free(ssl);
                            
                                }
                              
                            }
                            else {
                            std::string serverResponse = "400 Bad Request. Format is USER <username>";
                            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                            }

                            
                        }

                        if(receivedMsg.find("PASS") == 0) {
                            SSL *ssl = clientManager.getSSL(sock);
                            std::string serverResponse;
                            if(receivedMsg != "PASS" && receivedMsg != "PASS ")  {
                                if(clientManager.isPassModeOn(sock)) {

                                    std::string username = clientManager.getTempUsername(sock);
                                    std::string fullIVandPass = receivedMsg.substr(5);
                                    //std::cout << "Received fullIVandPass size: " << fullIVandPass.size() << std::endl;
                                    std::vector<unsigned char> iv(fullIVandPass.begin(), fullIVandPass.begin() + 16);
                                    std::vector<unsigned char> encryptedPassword(fullIVandPass.begin() + 16, fullIVandPass.end());
                                    std::string myPassword = decryptMyPassword(encryptedPassword, iv);
                                    std::string matchingSalt = getSaltFromFile(username);
                                    std::string saltedPass = saltPassword(myPassword, matchingSalt);
                                    std::string hashedSaltedPass = hashTheSaltedPassword(saltedPass);
                                    if(hashedSaltedPass == getHashFromFile(username)) {
                                        clientManager.heloCompleted(sock);
                                        std::string serverResponse = "You are logged in!";
                                        SSL_write(ssl, serverResponse.c_str(), serverResponse.size());
                                    }
                                    else {
                                        std::string serverResponse = "Incorrect Password, Please reissue PASS or choose a different USER";
                                        SSL_write(ssl, serverResponse.c_str(), serverResponse.size());
                                    }
                                    

                                }
                                else{
                            std::string serverResponse = "503 Bad sequence of commands.\nMust issue USER <username> command before issuing PASS";
                            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                                }
                                
            
                              
                            }
                            else {
                            std::string serverResponse = "400 Bad Request. Format is PASS <password>";
                            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                            }

                            
                        }



        //Check for HELP command
        //IF BEFORE HELO, WAIT FOR CONNECTION
             if(receivedMsg.find("HELP") == 0 && !(clientManager.isHELODone(sock))) {                                                             
                    std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
                        SSL *ssl = clientManager.getSSL(sock); 
                        SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                }

            //IF AFTER HELO, PROCEED
            if(clientManager.isHELODone(sock) && receivedMsg.find("HELP") == 0 && clientManager.getClientMode(sock) == "") {                       
                    std::string serverResponse = "200 Available commands:\nSEARCH, MANAGE, RECOMMEND, BYE";
                        SSL *ssl = clientManager.getSSL(sock); 
                        SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                }
                
             //IF AFTER HELO, in Search Mode
            if(clientManager.isHELODone(sock) && receivedMsg.find("HELP") == 0 && clientManager.getClientMode(sock) == "s") {                                                            
                    std::string serverResponse = "200 Avaiable commands: \nFIND <search_term>\nDETAILS <book_title>";
                     SSL *ssl = clientManager.getSSL(sock); 
                     SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                }

             //IF AFTER HELO, in Manage Mode
            if(clientManager.isHELODone(sock) && receivedMsg.find("HELP") == 0 && clientManager.getClientMode(sock) == "m") {                                                          
                    std::string serverResponse = "200 Avaiable commands: \nCHECKOUT <book_title>\nRETURN <book_title>\nLIST";
                        SSL *ssl = clientManager.getSSL(sock); 
                         SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                }

                 //IF AFTER HELO, in Recommend Mode
            if(clientManager.isHELODone(sock) && receivedMsg.find("HELP") == 0 && clientManager.getClientMode(sock) == "r") {                                                            
                    std::string serverResponse = "200 Avaiable commands: \nGET <genre>\nRATE <book_title> <rating>";
                        SSL *ssl = clientManager.getSSL(sock); 
                        SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
                }
                
              

        //Check for SEARCH command, activates search mode. Checks if HELO has been done already.
            if(receivedMsg.find("SEARCH") == 0 && !(clientManager.isHELODone(sock)) || receivedMsg == "SEARCH" && !(clientManager.isHELODone(sock))) {
                std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
                    SSL *ssl = clientManager.getSSL(sock); 
                    SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
            }
            
            if(receivedMsg.find("SEARCH") == 0 && clientManager.isHELODone(sock) || receivedMsg == "SEARCH" && clientManager.isHELODone(sock)) {
                std::string serverResponse = "210 Ready for search!";
                clientManager.setClientMode(sock, "s");
                    SSL *ssl = clientManager.getSSL(sock); 
                    SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
            }


           



        //Check for FIND command, Returns Book Title if found. Must be in search mode.
           if(receivedMsg.find("FIND ") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "s") {
            std::string serverResponse;
            if(receivedMsg != "FIND ") {
                
            std::string givenBookname = receivedMsg.substr(5);                  //Extract givenBookname
            
            
            bool bookFound = false;
            if(givenBookname.empty() || receivedMsg == "FIND") {
                serverResponse = "400 Bad Request. Format is FIND <book_title>";       
            }
            else {
            for(Book& book : books) {
                if(givenBookname == book.title) {
                    serverResponse = "250 " + book.title + "\n";                //Loop through books, find given title and return it.
                    bookFound = true;
                    break;
                }
            }
            if(!bookFound) {
                serverResponse = "304 No books found. Try again";
            }

            }
            }
            else {
                serverResponse = "400 Bad Request. Format is FIND <book_title>";
            }

            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }



            //THESE IF STATEMENTS HANDLE IF FIND IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("FIND") == 0 && !(clientManager.isHELODone(sock))) {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg.find("FIND") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "s") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter search mode using SEARCH command";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg == "FIND" && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "s") {
            std::string serverResponse = "400 Bad Request. Format is FIND <book_title>";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }




        //Check for DETAILS command, Returns book details if found. Must be in search mode.
           if(receivedMsg.find("DETAILS ") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "s") {
            std::string givenBookID = receivedMsg.substr(8);                        //Extract givenBookID
            std::string serverResponse;
            bool bookFound = false; 
            for(Book& book : books) {                       //Loop through books and find given title and return all details.
                if(givenBookID == book.title) {
                    serverResponse = "250\n" + book.title + "\nBy: " + book.author + "\nGenre: " + book.genre + "\nRating: " + std::to_string(book.rating) + "\n";
                    if(book.available == true) {
                       serverResponse += "Available";
                    }
                    else {
                        serverResponse += "Checked Out";
                    }
                    bookFound = true;
                    break;
                }
            }
            if(!bookFound) {
                serverResponse = "404 No book found matching " + givenBookID + ". Please try again";
            }

            
            
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           //THESE IF STATEMENTS HANDLE IF DETAILS IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("DETAILS") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "s") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter search mode using SEARCH command";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           if(receivedMsg.find("DETAILS") == 0 && !(clientManager.isHELODone(sock)) && clientManager.getClientMode(sock) != "s") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg == "DETAILS" && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "s") {
            std::string serverResponse = "400 Bad Request. Format is DETAILS <book_title>";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }



        //Check for MANAGE command, activate manageMode. Checks if it happens after HELO
        if(receivedMsg.find("MANAGE") == 0 && !(clientManager.isHELODone(sock)) || receivedMsg == "MANAGE" && !(clientManager.isHELODone(sock))) {
                std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
            }
            
            if(receivedMsg.find("MANAGE") == 0 && clientManager.isHELODone(sock) || receivedMsg == "MANAGE" && clientManager.isHELODone(sock)) {
                std::string serverResponse = "210 Ready for book management!";
                clientManager.setClientMode(sock, "m");
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
            }



            //Check for CHECKOUT command, checks out book if avaible. Must be in manage mode.
           if(receivedMsg.find("CHECKOUT ") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "m") {
            std::string givenBookID = receivedMsg.substr(9);                                //Extract givenBookID
            std::string serverResponse;
            bool bookFound = false;
            for(Book& book : books) {
                if(givenBookID == book.title) {                                   //Loop through books and find given title, if available then return it.
                    
                    if(book.available == true) {                                            
                       serverResponse = "250 You have checked out " + book.title;
                       bookFound = true;
                       book.available = false;
                    }
                    else {
                        serverResponse = "403 "+ book.title + " is unavaiable";
                        bookFound = true;
                    }
                    
                }
            }
            if(!bookFound) {
                serverResponse = "404 No book found matching " + givenBookID + ". Please try again";
            }

            
            
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }



            //THESE IF STATEMENTS HANDLE IF CHECKOUT IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("CHECKOUT") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "m") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter manage mode using MANAGE command";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           if(receivedMsg.find("CHECKOUT") == 0 && !(clientManager.isHELODone(sock)) && clientManager.getClientMode(sock) != "m") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg == "CHECKOUT" && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "m") {
            std::string serverResponse = "400 Bad Request. Format is CHECKOUT <book_title>";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }



            //RETURN COMMAND, returns checked out book.
           if(receivedMsg.find("RETURN ") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "m") {
            std::string givenBookID = receivedMsg.substr(7);                //extract givenBookID
            std::string serverResponse;
            bool bookFound = false;
            for(Book& book : books) {
                if(givenBookID == book.title) {                                 //Loop through books and find given title, if unavailable(checked out), return it.
                    
                    if(book.available == true) {
                       serverResponse = "404 " + book.title + " is not checked out";
                       bookFound = true;
                    }
                    else {
                        serverResponse = "250 "+ book.title + " has been returned";
                        bookFound = true;
                        book.available = true;
                    }
                    
                }
            }
            if(!bookFound) {
                serverResponse = "404 No book found matching " + givenBookID + ". Please try again";
            }

            
            
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }


            //THESE IF STATEMENTS HANDLE IF RETURN IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("RETURN") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "m") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter manage mode using MANAGE command";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           if(receivedMsg.find("RETURN") == 0 && !(clientManager.isHELODone(sock)) && clientManager.getClientMode(sock) != "m") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg == "RETURN" && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "m") {
            std::string serverResponse = "400 Bad Request. Format is RETURN <book_title>";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }




            //LIST Command, returns all available books.
           if(receivedMsg.find("LIST") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "m") {
            
            std::string serverResponse;
            bool statusCode = false;                //Makes sure 200 is issued by changing bool when it is.
            
            for(Book& book : books) {               //Loop through books and return titles of all 

                if(book.available == true && statusCode) {              
                    
                       serverResponse += "\n" + book.title;
                    } 

                    if(book.available == true && !statusCode) {
                        serverResponse += "200";
                       serverResponse += "\n" + book.title;
                       statusCode = true;
                    } 
                    
                
            }
            if(serverResponse.empty()) {
                serverResponse = "304 No books are avaiable.";
            }

            
             SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }


            //THESE IF STATEMENTS HANDLE IF LIST IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("LIST") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "m") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter manage mode using MANAGE command";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           if(receivedMsg.find("LIST") == 0 && !(clientManager.isHELODone(sock)) && clientManager.getClientMode(sock) != "m") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }





           //Check for RECOMMEND command, activate manageMode. Checks if HELO has been called before
        if(receivedMsg.find("RECOMMEND") == 0 && !(clientManager.isHELODone(sock)) || receivedMsg == "RECOMMEND" && !(clientManager.isHELODone(sock))) {
                std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
            }
            
            if(receivedMsg.find("RECOMMEND") == 0 && clientManager.isHELODone(sock) || receivedMsg == "RECOMMEND" && clientManager.isHELODone(sock)) {
                std::string serverResponse = "210 Ready for book recommendation!";
                clientManager.setClientMode(sock, "r");
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
            }






            //GET command, returns book recommendations
           if(receivedMsg.find("GET ") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "r") {
            std::string givenBookGenre = receivedMsg.substr(4);             //extract givenBookGenre
            std::string serverResponse;
            bool statusCode = false;                                    //bool to make sure 200 is printed once if multiple books are found.
            
            
            for(Book& book : books) {

                if(givenBookGenre == book.genre && statusCode)
                serverResponse += "\n" + book.title;                  //Loop through all books, if genre matches, print it

                if(givenBookGenre == book.genre && !statusCode) {
                serverResponse += "200";
                serverResponse += "\n" + book.title;
                statusCode = true; }

                

                    } 
                
            
            if(serverResponse.empty()) {
                serverResponse = "304 No books are avaiable.";
            }

            
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           


         //THESE IF STATEMENTS HANDLE IF GET IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("GET") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "r") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter recommendation mode using RECOMMEND command";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           if(receivedMsg.find("GET") == 0 && !(clientManager.isHELODone(sock)) && clientManager.getClientMode(sock) != "r") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg == "GET" && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "r") {
            std::string serverResponse = "400 Bad Request. Format is GET <genre>";
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }





            //RATE command, returns book recommendations
          if (receivedMsg.find("RATE ") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "r") {
           std::string givenBook;
           int givenIntBookRating;
           std::string serverResponse;
           bool foundBook = false;
           bool validName = false;
           bool validRating = false;
           bool isString = true;
           std::string extractedString;
           size_t position = 5;                                 //set position so you can start reading string after RATE 
           size_t space;

    
          while (isString && position < receivedMsg.size()) {
             space = receivedMsg.find(" ", position);                 // Find the next space, if there isnt one, make = to size to make it last word. 
               if (space == std::string::npos) {                       
                  space = receivedMsg.size();                    
              }

              extractedString = receivedMsg.substr(position, space - position);                     // Extract word from position

        
           try {
               givenIntBookRating = std::stoi(extractedString);                      // Try to convert extractedString to integer, if not possible, then title is not done, go to catch

                  if (givenIntBookRating >= 1 && givenIntBookRating <= 5) {              
                     validRating = true;
                     isString = false;                                                  //rating found, end loop
                    } else {
                        serverResponse = "400 BAD REQUEST, rating must be between 1 and 5";
                       break;
                   }
               } catch (std::invalid_argument&) {
                                                                            // If extractedString is not an integer(catch), keep adding to string
                   if (!givenBook.empty()) {
                       givenBook += " ";  
                    }
                   givenBook += extractedString; 
              }

              position = space + 1;                                         //set at next space after string you just extracted.
           }

    
           if (!givenBook.empty() && validRating) {
               validName = true;

              for (Book& book : books) {
                 if (givenBook == book.title) {                         //Loop through books, if title found, return title and save rating
                        book.rating = givenIntBookRating;
                        foundBook = true;
                        serverResponse = "250 " + book.title + " has been rated a " + std::to_string(givenIntBookRating);
                        break;
                    }
              }

             if (!foundBook) {
                  serverResponse = "404 NOT FOUND, book not found";
              }
         } else if (!validName || !validRating) {
                serverResponse = "400 BAD REQUEST, format is RATE <book_title> <rating>";
          }

    
            SSL *ssl = clientManager.getSSL(sock); 
            SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
        }
           


            //THESE IF STATEMENTS HANDLE IF RATE IS CALLED IN WRONG MODE OR BEFORE HELO COMMAND
           if(receivedMsg.find("RATE") == 0 && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) != "r") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust enter recommendation mode using RECOMMEND command";
                        SSL *ssl = clientManager.getSSL(sock); 
                        SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }

           if(receivedMsg.find("RATE") == 0 && !(clientManager.isHELODone(sock)) && clientManager.getClientMode(sock) != "r") {
            std::string serverResponse = "503 Bad sequence of commands.\nMust initialize connection with USER/PASS commands";
                        SSL *ssl = clientManager.getSSL(sock); 
                     SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }
           if(receivedMsg == "RATE" && clientManager.isHELODone(sock) && clientManager.getClientMode(sock) == "r") {
            std::string serverResponse = "400 Bad Request. Format is RATE <book_title> <rating>";
                SSL *ssl = clientManager.getSSL(sock); 
                SSL_write(ssl, serverResponse.c_str(), serverResponse.size()); 
           }


           
            

   
          






                        
       }



                }
            }
        }
    }
    
    SSL *ssl = clientManager.getSSL(sockfd);
    SSL_free(ssl);
    close(sockfd);
    FD_CLR(sockfd, &socket_list);
    
    return 0;
}

                           
