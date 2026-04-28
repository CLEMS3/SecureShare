#include "NetworkManager.h"
#include <iostream>
#include <cstring>

int NetworkManager::host(int port) {
    int server_socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        std::cerr << "Failed to create server socket.\n";
        return -1;
    }

    int opt = 1;
    ::setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (::bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Bind failed.\n";
        return -1;
    }

    if (::listen(server_socket, SOMAXCONN) < 0) {
        std::cerr << "Listen failed.\n";
        return -1;
    }

    std::cout << "[System] Node listening on " << getLocalIP() << ":" << port << "...\n";
    return server_socket;
}

int NetworkManager::acceptConnection(int server_socket) {
    sockaddr_in client_addr{};
    socklen_t client_len = sizeof(client_addr);
    int connection_socket = ::accept(server_socket, (struct sockaddr*)&client_addr, &client_len);

    if (connection_socket < 0) {
        return -1;
    }
    return connection_socket;
}

int NetworkManager::connectTo(const std::string& ip, int port) {
    int connection_socket = ::socket(AF_INET, SOCK_STREAM, 0);
    if (connection_socket == -1) {
        std::cerr << "Failed to create client socket.\n";
        return -1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);

    if (inet_pton(AF_INET, ip.c_str(), &server_addr.sin_addr) <= 0) {
        std::cerr << "Invalid address / Address not supported\n";
        return -1;
    }

    if (::connect(connection_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        std::cerr << "Connection failed.\n";
        return -1;
    }

    return connection_socket;
}

bool NetworkManager::sendAll(int socket, const char* buffer, size_t length) {
    size_t total_sent = 0;
    while (total_sent < length) {
        ssize_t sent = ::send(socket, buffer + total_sent, length - total_sent, 0);
        if (sent <= 0) return false;
        total_sent += sent;
    }
    return true;
}

bool NetworkManager::receiveAll(int socket, char* buffer, size_t length) {
    size_t total_received = 0;
    while (total_received < length) {
        ssize_t received = ::recv(socket, buffer + total_received, length - total_received, 0);
        if (received <= 0) return false;
        total_received += received;
    }
    return true;
}

bool NetworkManager::sendData(int socket, const std::vector<uint8_t>& data) {
    if (socket == -1) return false;

    // Send length prefix (4 bytes)
    uint32_t length = htonl(data.size());
    if (!sendAll(socket, reinterpret_cast<const char*>(&length), sizeof(length))) {
        return false;
    }

    // Send payload
    if (data.size() > 0) {
        return sendAll(socket, reinterpret_cast<const char*>(data.data()), data.size());
    }
    return true;
}

bool NetworkManager::receiveData(int socket, std::vector<uint8_t>& data) {
    if (socket == -1) return false;

    // Receive length prefix
    uint32_t nlength;
    if (!receiveAll(socket, reinterpret_cast<char*>(&nlength), sizeof(nlength))) {
        return false;
    }

    uint32_t length = ntohl(nlength);
    data.resize(length);

    // Receive payload
    if (length > 0) {
        return receiveAll(socket, reinterpret_cast<char*>(data.data()), length);
    }
    return true;
}

bool NetworkManager::sendString(int socket, const std::string& str) {
    std::vector<uint8_t> data(str.begin(), str.end());
    return sendData(socket, data);
}

bool NetworkManager::receiveString(int socket, std::string& str) {
    std::vector<uint8_t> data;
    if (!receiveData(socket, data)) return false;
    str.assign(data.begin(), data.end());
    return true;
}

void NetworkManager::closeSocket(int socket) {
    if (socket != -1) {
        ::close(socket);
    }
}

std::string NetworkManager::getLocalIP() {
    std::string local_ip = "127.0.0.1";
    int dummy_sock = ::socket(AF_INET, SOCK_DGRAM, 0);
    if (dummy_sock >= 0) {
        struct sockaddr_in serv{};
        serv.sin_family = AF_INET;
        inet_pton(AF_INET, "8.8.8.8", &serv.sin_addr);
        serv.sin_port = htons(53);
        if (::connect(dummy_sock, (const struct sockaddr*)&serv, sizeof(serv)) == 0) {
            struct sockaddr_in name{};
            socklen_t namelen = sizeof(name);
            if (::getsockname(dummy_sock, (struct sockaddr*)&name, &namelen) == 0) {
                char buffer[INET_ADDRSTRLEN];
                if (inet_ntop(AF_INET, &name.sin_addr, buffer, sizeof(buffer))) {
                    local_ip = buffer;
                }
            }
        }
        ::close(dummy_sock);
    }
    return local_ip;
}

bool NetworkManager::setSocketTimeout(int socket, int seconds) {
    if (socket == -1) return false;
    struct timeval tv;
    tv.tv_sec = seconds;
    tv.tv_usec = 0;
    if (::setsockopt(socket, SOL_SOCKET, SO_RCVTIMEO, (const void*)&tv, sizeof(tv)) < 0) return false;
    if (::setsockopt(socket, SOL_SOCKET, SO_SNDTIMEO, (const void*)&tv, sizeof(tv)) < 0) return false;
    return true;
}
