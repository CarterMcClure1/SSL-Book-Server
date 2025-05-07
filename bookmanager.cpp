#include <iostream>
#include <string>
#include <vector>
#include <fstream>
#include <sstream>
#include <map>
#include <openssl/ssl.h>
#include <openssl/err.h>



struct Book {
    std::string title;
    std::string author;
    std::string genre;
    bool available; // true if available for checkout, false otherwise
    int rating; // 1-5 stars, 0 if not yet rated
};


class Client {

public:
    int socketnum;
    SSL* ssl = nullptr;
    std::string nickname;
    std::string username;
    std::string realname;
    bool HELO = false;
    bool nickIsSet = false;
    bool usernameIsSet = false;
    std::string userMode = "";
    bool passwordMode = false;
    bool isLoggedIn = false;
    std::string tempUsername;
    
    


    Client() {
        this->socketnum = -1;
        this->nickname = "(No Nickname Set)";

    }

    
    Client(int sockfd, const std::string& nick = "") {
        this->socketnum = sockfd;
        this->nickname = nick;
    }

        
    
    // Method to set nickname
    void setNickname(const std::string& nick) {
        this->nickname = nick;
        
    }

     

    void setUsername(const std::string& name) {
        this->username = name;
    }

    

    void setTempUsername(const std::string& name) {
        this->tempUsername = name;
    }

    std::string getTempUsername() {
        return this->tempUsername; 
        }


    void setMode(std::string mode) {
        this->userMode= mode;
    }

    std::string getMode() const {
        return this->userMode;
    }

    int getSocketNumber() const {
        return this->socketnum;
    }



    // Method to retrieve nickname
    std::string getNickname() const {
        return this->nickname;
    }

    std::string getUsername() const {
        return this->username;
    }

    

};

class ClientManager {
public:
    

    std::map<int, Client> clients;
    

     void addClient(int sock) {
        clients[sock] = Client(sock);  // Insert a new client with the socket number
        
    }

    void heloCompleted(int sock) {
        if (clients.find(sock) != clients.end()) {
            clients[sock].HELO = true;
        }
    }

    bool isHELODone(int sock) {
        if(clients.find(sock) != clients.end()) {
            return clients[sock].HELO;
        }
        return false;
    }

    void enterPassMode(int sock) {
        if (clients.find(sock) != clients.end()) {
            clients[sock].passwordMode = true;
        }
    }

    bool isPassModeOn(int sock) {
        if(clients.find(sock) != clients.end()) {
            return clients[sock].passwordMode;
        }
        return false;
    }

    void userIsLoggedIn(int sock) {
        if (clients.find(sock) != clients.end()) {
            clients[sock].isLoggedIn = true;
        }
    }

    

    bool isUserLoggedIn(int sock) {
        if(clients.find(sock) != clients.end()) {
            return clients[sock].isLoggedIn;
        }
        return false;
    }

    std::string getTempUsername(int sock) {
        if (clients.find(sock) != clients.end()) {
            return clients[sock].getTempUsername();
        }
        return "Not available";
    }

    void setTempUsername(int sock, std::string name) {
        if (clients.find(sock) != clients.end()) {
           clients[sock].setTempUsername(name);
        }
       
    }


    std::string getClientMode(int sock) {
        if (clients.find(sock) != clients.end()) {
            return clients[sock].getMode();
        }
        return "No mode available";
    }

    void setClientMode(int sock, std::string mode) {
        if (clients.find(sock) != clients.end()) {
           clients[sock].setMode(mode);
        }
       
    }

    void addSSL(int sock, SSL* ssl) {
        if (clients.find(sock) != clients.end()) {
            clients[sock].ssl = ssl; // Associate the SSL object with the client
        }
    }

    SSL* getSSL(int sock) {
        if (clients.find(sock) != clients.end()) {
            return clients[sock].ssl; // Retrieve the SSL object for the client
        }
        return nullptr; // Return nullptr if client doesn't exist
    }

};


class BookManager {
public:
    std::string userMode = "";

    BookManager() {
        
    }


std::vector<Book> loadBooksFromFile(const std::string& filename) {
    std::vector<Book> books;
    std::ifstream file(filename);
    std::string line;

    // Skip header line
    std::getline(file, line);

    while (std::getline(file, line)) {
        std::stringstream ss(line);
        std::string title, author, genre, available_str, rating_str;

        std::getline(ss, title, ';');
        std::getline(ss, author, ';');
        std::getline(ss, genre, ';');
        std::getline(ss, available_str, ';');
        std::getline(ss, rating_str, ';');

        Book book;
        book.title = title;
        book.author = author;
        book.genre = genre;
        book.available = (available_str == "true");
        book.rating = std::stoi(rating_str);

        books.push_back(book);
    }

    return books;
}



};