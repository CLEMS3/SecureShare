#ifndef NETWORK_MANAGER_H
#define NETWORK_MANAGER_H

#include <string>
#include <vector>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

class NetworkManager {
public:
    NetworkManager() {}
    ~NetworkManager() {}

    // Sets up the socket to listen on a port and returns server socket
    int host(int port);

    // Accept connection on a server socket
    int acceptConnection(int server_socket);

    // Connects to a remote host and returns the connection socket
    int connectTo(const std::string& ip, int port);

    // Sends data over the established connection
    bool sendData(int socket, const std::vector<uint8_t>& data);
    bool sendString(int socket, const std::string& str);

    // Receives data (blocks until data is available)
    bool receiveData(int socket, std::vector<uint8_t>& data);
    bool receiveString(int socket, std::string& str);

    static void closeSocket(int socket);

    // Timeout control
    static bool setSocketTimeout(int socket, int seconds);

private:
    bool sendAll(int socket, const char* buffer, size_t length);
    bool receiveAll(int socket, char* buffer, size_t length);
};

#endif // NETWORK_MANAGER_H
