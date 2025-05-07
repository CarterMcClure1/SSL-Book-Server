#include <iostream>
#include <fstream>
#include <string>
#include <cstring>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "bookmanager.cpp"


constexpr size_t MAXDATASIZE = 300;

void* get_in_addr(struct sockaddr* sa) {
    if (sa->sa_family == AF_INET) {
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }
    return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

SSL_CTX *create_myclient_context() {
    SSL_CTX *ctx;

    // Use the TLS client method
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    // Set protocol version to TLS 1.3
    SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);
    SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);

    
    SSL_CTX_load_verify_locations(ctx, "p3server.crt", nullptr);

   
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);

    return ctx;
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


int main(int argc, char* argv[]) {
    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    SSL_CTX *ctx = create_myclient_context();
    

    if (argc != 2) {
        std::cerr << "usage: client client.conf\n";
        return 1;
    }

    // Read config file
    std::string serverIP, serverPort;
    std::ifstream configFile(argv[1]);
    if (!configFile.is_open()) {
        std::cerr << "Error opening config file: " << argv[1] << std::endl;
        return 1;
    }

    std::string line;
    while (std::getline(configFile, line)) {
        if (line.find("SERVER_IP=") == 0) {
            serverIP = line.substr(10);
        } else if (line.find("SERVER_PORT=") == 0) {
            serverPort = line.substr(12);
        }
    }
    configFile.close();

    serverIP.erase(0, serverIP.find_first_not_of(" \t\n\r"));
    serverIP.erase(serverIP.find_last_not_of(" \t\n\r") + 1);

    serverPort.erase(0, serverPort.find_first_not_of(" \t\n\r"));
    serverPort.erase(serverPort.find_last_not_of(" \t\n\r") + 1);

    if (serverIP.empty() || serverPort.empty()) {
        std::cerr << "Invalid config file format.\n";
        return 1;
    }

    // Set up connection hints
    addrinfo hints, *servinfo, *p;
    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    // Get address information
    int rv = getaddrinfo(serverIP.c_str(), serverPort.c_str(), &hints, &servinfo);
    if (rv != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rv) << std::endl;
        return 1;
    }

    int sockfd;
    // Loop through results and try to connect
    for (p = servinfo; p != nullptr; p = p->ai_next) {
        sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sockfd == -1) {
            perror("client: socket");
            continue;
        }

        if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
            perror("client: connect");
            close(sockfd);
            continue;
        }

        break;
    }

    if (p == nullptr) {
        std::cerr << "client: failed to connect\n";
        return 2;
    }

    // Display connection info
    char s[INET6_ADDRSTRLEN];
    inet_ntop(p->ai_family, get_in_addr((struct sockaddr*)p->ai_addr), s, sizeof s);
    std::cout << "client: connecting to " << s << std::endl;

    freeaddrinfo(servinfo);

     SSL* ssl = SSL_new(ctx);
     if (!ssl) {
    perror("Unable to create SSL structure");
    ERR_print_errors_fp(stderr);
    close(sockfd);
    SSL_CTX_free(ctx);
    return 1;
}
     SSL_set_fd(ssl, sockfd);

     if (SSL_connect(ssl) <= 0) {
    int err = SSL_get_error(ssl, -1);
    fprintf(stderr, "SSL_connect failed with error code: %d\n", err);
    ERR_print_errors_fp(stderr);
    return -1;
}

    std::cout << "SSL connection established using the cipher: " << SSL_get_cipher(ssl) << std::endl;


    //After client connects, obtain TCP port it was assigned 
    sockaddr_in localAddr;
    socklen_t addrLen = sizeof(localAddr);
    if (getsockname(sockfd, (struct sockaddr*)&localAddr, &addrLen) == -1) {
        perror("getsockname");
        close(sockfd);
        return 1;
    }

    

    


    char buf[MAXDATASIZE];
    std::string userInput;


    fd_set tempsocklist;
    int maxsocknumber;

    //fcntl(sockfd, F_SETFL, O_NONBLOCK);

while (true) {
    FD_ZERO(&tempsocklist);
    FD_SET(sockfd, &tempsocklist);          //set up temp socket list
    FD_SET(STDIN_FILENO, &tempsocklist);    //set user input

    maxsocknumber = std::max(sockfd, STDIN_FILENO);

   

    // Use select to wait for activity from server or user
    if (select(maxsocknumber + 1, &tempsocklist, nullptr, nullptr, nullptr) == -1) {
        perror("select");
        break;
    }

    // Check for input from user
    if (FD_ISSET(STDIN_FILENO, &tempsocklist)) {
    std::cout << "> ";
    std::getline(std::cin, userInput);
    if (userInput == "exit") {
        break;
    }

    bool isSent = false;
    if(userInput.rfind("PASS ", 0) == 0) {
        std::string password = userInput.substr(5);
         std::vector<unsigned char> iv = generateRandomInitialVector();
         std::vector<unsigned char> encryptedPassword = encryptMyPassword(password, iv);

        std::string ivString(iv.begin(), iv.end());
        //std::cout << ivString;
        std::string encryptedPasswordString(encryptedPassword.begin(), encryptedPassword.end());
        //std::cout <<encryptedPasswordString;
        std::string newInput = "PASS " + ivString + encryptedPasswordString;
        if (SSL_write(ssl, newInput.c_str(), newInput.size()) <= 0) {
        perror("SSL_write");
        break;
    }
    isSent = true;
 
    }

    if(!isSent) {
    if (SSL_write(ssl, userInput.c_str(), userInput.size()) <= 0) {
        perror("SSL_write");
        break;
    }
    }
    
    
} 

    // Check for tcp packet from server
    if (FD_ISSET(sockfd, &tempsocklist)) {
    int numbytes = SSL_read(ssl, buf, MAXDATASIZE - 1);
    if (numbytes <= 0) {
        int sslErr = SSL_get_error(ssl, numbytes);
        if (sslErr == SSL_ERROR_WANT_READ || sslErr == SSL_ERROR_WANT_WRITE) {
            // Retry later when the socket is ready
            continue;
        } else {
            perror("SSL_read");
            break;
        }
    }
    buf[numbytes] = '\0';
    if (buf[0] == '@') {
        std::string receivedData(buf + 1, numbytes - 1);

        // Extract the IV (assuming IV size is fixed, e.g., 16 bytes for AES)
        std::vector<unsigned char> iv(receivedData.begin(), receivedData.begin() + 16);

        // Extract the encrypted password
         std::vector<unsigned char> encryptedPassword(receivedData.begin() + 16, receivedData.end());
         std::string myPassword = decryptMyPassword(encryptedPassword, iv);

        std::cout << "You can now login, Your password for your new account is: " << myPassword << std::endl;
        
    }
    else {
    std::cout << buf << std::endl; }

}


    
}

    
    SSL_free(ssl);
    close(sockfd);
    SSL_CTX_free(ctx);
    EVP_cleanup();
    return 0;
}