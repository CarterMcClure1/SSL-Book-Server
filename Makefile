all:
	g++ server.cpp -o server -lssl -lcrypto
	g++ client.cpp -o client -lssl -lcrypto

clean:
	rm -f server client