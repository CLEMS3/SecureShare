#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <fstream>
#include <filesystem>
#include <vector>
#include <cstring>
#include <map>
#include <mutex>
#include <memory>
#include <arpa/inet.h>
#include <csignal>
#include <sstream>
#include "NetworkManager.h"
#include "CryptoHandler.h"

std::atomic<bool> appRunning(true);
std::string my_name;
int listen_port;
NetworkManager net;

struct PeerConnection {
    int socket;
    std::unique_ptr<CryptoHandler> crypto;
    std::string peer_name;
    std::mutex send_mutex;
    std::atomic<bool> active{true};
    
    // File sending state
    std::atomic<bool> fileReqWait{false};
    std::atomic<uint32_t> resumeOffset{0};

    // File receiving state
    std::unique_ptr<std::ofstream> active_recv_file;
    std::string active_recv_filename;
    uint32_t active_recv_total_size{0};
    uint32_t active_recv_progress_size{0};
    int active_recv_last_pct{-1};

    PeerConnection() : active_recv_file(nullptr) {}
};

std::map<std::string, std::shared_ptr<PeerConnection>> active_peers;
std::mutex peers_mutex;
int server_sock_global = -1;

void packet_send_msg(std::shared_ptr<PeerConnection> peer, const std::string& msg) {
    std::vector<uint8_t> plain(1 + msg.size());
    plain[0] = 0x00;
    std::memcpy(&plain[1], msg.data(), msg.size());
    try {
        std::lock_guard<std::mutex> lock(peer->send_mutex);
        std::vector<uint8_t> cipher = peer->crypto->encrypt(plain);
        net.sendData(peer->socket, cipher);
    } catch (...) {}
}

bool performHandshake(int socket, std::shared_ptr<PeerConnection> peer, bool isInitiator) {
    if (!peer->crypto->generateECDHKeyPair()) return false;
    
    if (!net.sendData(socket, peer->crypto->getPublicKey())) return false;
    
    std::vector<uint8_t> peer_pub_key;
    if (!net.receiveData(socket, peer_pub_key)) return false;
    
    if (!peer->crypto->computeSharedSecret(peer_pub_key)) return false;

    // Exchange names
    std::string their_name;
    try {
        if (isInitiator) {
            std::vector<uint8_t> my_name_plain(my_name.begin(), my_name.end());
            net.sendData(socket, peer->crypto->encrypt(my_name_plain));
            
            std::vector<uint8_t> their_name_cipher;
            if (!net.receiveData(socket, their_name_cipher)) return false;
            std::vector<uint8_t> their_name_plain = peer->crypto->decrypt(their_name_cipher);
            their_name.assign(their_name_plain.begin(), their_name_plain.end());
        } else {
            std::vector<uint8_t> their_name_cipher;
            if (!net.receiveData(socket, their_name_cipher)) return false;
            std::vector<uint8_t> their_name_plain = peer->crypto->decrypt(their_name_cipher);
            their_name.assign(their_name_plain.begin(), their_name_plain.end());
            
            std::vector<uint8_t> my_name_plain(my_name.begin(), my_name.end());
            net.sendData(socket, peer->crypto->encrypt(my_name_plain));
        }
    } catch (...) {
        return false;
    }

    peer->peer_name = their_name;
    return true;
}

void sendFileWorker(std::string filePath, uint32_t offset, uint32_t totalSize, std::shared_ptr<PeerConnection> peer) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        std::cerr << "\n[System] Failed to open file for sending.\n> ";
        std::cout.flush();
        return;
    }
    file.seekg(offset);
    
    std::filesystem::path p(filePath);
    std::string filename = p.filename().string();
    
    const size_t CHUNK_SIZE = 65536; // 64KB
    std::vector<uint8_t> buffer(CHUNK_SIZE);
    
    uint32_t sent = offset;
    int lastPercent = -1;

    while (file && peer->active && appRunning) {
        file.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
        size_t bytesRead = file.gcount();
        if (bytesRead == 0) break;
        
        std::vector<uint8_t> plain(1 + bytesRead);
        plain[0] = 0x04; // chunk type
        std::memcpy(&plain[1], buffer.data(), bytesRead);
        
        try {
            std::lock_guard<std::mutex> lock(peer->send_mutex);
            std::vector<uint8_t> cipher = peer->crypto->encrypt(plain);
            if (!net.sendData(peer->socket, cipher)) {
                 break; // connection dropped mid transfer
            }
        } catch (...) { break; }

        sent += bytesRead;
        int pct = (totalSize > 0) ? (int)((sent * 100.0) / totalSize) : 100;
        if (pct != lastPercent && pct % 10 == 0) {
            std::cout << "\n[System] Uploading to " << peer->peer_name << "... " << pct << "%\n> ";
            std::cout.flush();
            lastPercent = pct;
        }
    }
    
    if (peer->active && appRunning) {
        std::vector<uint8_t> plain(1, 0x05); // EOF type
        try {
            std::lock_guard<std::mutex> lock(peer->send_mutex);
            net.sendData(peer->socket, peer->crypto->encrypt(plain));
            std::cout << "\n[System] File transfer of " << filename << " to " << peer->peer_name << " completed.\n> ";
            std::cout.flush();
        } catch (...) {}
    }
}

void receiveThread(std::shared_ptr<PeerConnection> peer) {
    while (peer->active && appRunning) {
        std::vector<uint8_t> data;
        if (!net.receiveData(peer->socket, data)) {
            std::cout << "\n[System] Connection lost with " << peer->peer_name << ".\n> ";
            std::cout.flush();
            peer->active = false;
            break;
        }

        try {
            std::vector<uint8_t> decrypted = peer->crypto->decrypt(data);
            if (decrypted.empty()) continue;

            uint8_t type = decrypted[0];

            if (type == 0x00) {
                std::string msg(decrypted.begin() + 1, decrypted.end());
                std::cout << "\n[" << peer->peer_name << "]: " << msg << "\n> ";
                std::cout.flush();
            } else if (type == 0x02) {
                if (decrypted.size() < 7) continue;
                uint32_t size_net;
                std::memcpy(&size_net, &decrypted[1], 4);
                uint32_t totalSize = ntohl(size_net);
                
                uint16_t namelen_net;
                std::memcpy(&namelen_net, &decrypted[5], 2);
                uint16_t namelen = ntohs(namelen_net);
                
                if (decrypted.size() < 7ULL + namelen) continue;
                std::string name(decrypted.begin() + 7, decrypted.begin() + 7 + namelen);
                
                std::string name_stem = std::filesystem::path(name).stem().string();
                std::string name_ext = std::filesystem::path(name).extension().string();
                std::string baseSavePath = "received_" + name;
                
                int counter = 1;
                while (std::filesystem::exists(baseSavePath)) {
                    baseSavePath = "received_" + name_stem + "_" + std::to_string(counter) + name_ext;
                    counter++;
                }
                
                std::string savePath = baseSavePath + ".part";
                peer->active_recv_filename = baseSavePath;
                
                uint32_t offset = 0;
                if (std::filesystem::exists(savePath)) {
                    offset = std::filesystem::file_size(savePath);
                    if (offset > totalSize) offset = totalSize;
                }
                
                if (peer->active_recv_file && peer->active_recv_file->is_open()) peer->active_recv_file->close();
                peer->active_recv_file = std::make_unique<std::ofstream>(savePath, std::ios::binary | std::ios::app);
                
                peer->active_recv_total_size = totalSize;
                peer->active_recv_progress_size = offset;
                peer->active_recv_last_pct = (totalSize > 0) ? (int)((offset * 100.0) / totalSize) : 100;

                std::vector<uint8_t> plain(7 + namelen);
                plain[0] = 0x03;
                uint32_t offset_net = htonl(offset);
                std::memcpy(&plain[1], &offset_net, 4);
                std::memcpy(&plain[5], &namelen_net, 2);
                std::memcpy(&plain[7], name.data(), namelen);
                
                {
                    std::lock_guard<std::mutex> lock(peer->send_mutex);
                    net.sendData(peer->socket, peer->crypto->encrypt(plain));
                }
                std::cout << "\n[System] " << peer->peer_name << " is sending file '" << name << "', receiving from byte " << offset << "...\n> ";
                std::cout.flush();

            } else if (type == 0x03) {
                if (decrypted.size() < 7) continue;
                uint32_t offset_net;
                std::memcpy(&offset_net, &decrypted[1], 4);
                peer->resumeOffset = ntohl(offset_net);
                peer->fileReqWait = false;
            } else if (type == 0x04) {
                if (peer->active_recv_file && peer->active_recv_file->is_open()) {
                    peer->active_recv_file->write(reinterpret_cast<const char*>(decrypted.data() + 1), decrypted.size() - 1);
                    peer->active_recv_progress_size += (decrypted.size() - 1);

                    int pct = (peer->active_recv_total_size > 0) ? (int)((peer->active_recv_progress_size * 100.0) / peer->active_recv_total_size) : 100;
                    if (pct != peer->active_recv_last_pct && pct % 10 == 0) {
                        std::cout << "\n[System] Downloading from " << peer->peer_name << "... " << pct << "%\n> ";
                        std::cout.flush();
                        peer->active_recv_last_pct = pct;
                    }
                }
            } else if (type == 0x05) {
                if (peer->active_recv_file && peer->active_recv_file->is_open()) peer->active_recv_file->close();
                
                std::string finalPath = peer->active_recv_filename;
                std::string partPath = finalPath + ".part";
                if (std::filesystem::exists(partPath)) {
                    std::error_code ec;
                    std::filesystem::rename(partPath, finalPath, ec);
                    if (ec) {
                        std::cerr << "\n[System] Warning: could not rename .part file: " << ec.message() << "\n> ";
                        std::cout.flush();
                    }
                }

                std::cout << "\n[System] File totally received from " << peer->peer_name << " & saved as: " << finalPath << "\n> ";
                std::cout.flush();
            } else if (type == 0x06) {
                std::cout << "\n[System] Peer '" << peer->peer_name << "' has disconnected cleanly.\n> ";
                std::cout.flush();
                peer->active = false;
                break;
            } else if (type == 0x07) {
                std::vector<uint8_t> plain(1, 0x08); // Pong type
                std::lock_guard<std::mutex> lock(peer->send_mutex);
                net.sendData(peer->socket, peer->crypto->encrypt(plain));
            } else if (type == 0x08) {
                // Pong received, keeps the read block alive, no action needed
            }

        } catch (const std::exception& e) {
            std::cerr << "\n[System] Failed to decrypt message from " << peer->peer_name << ": " << e.what() << "\n> ";
            std::cout.flush();
        }
    }
    
    // Cleanup
    net.closeSocket(peer->socket);
    std::lock_guard<std::mutex> lock(peers_mutex);
    active_peers.erase(peer->peer_name);
}

void pingThread() {
    while (appRunning) {
        std::this_thread::sleep_for(std::chrono::seconds(30));
        std::vector<std::shared_ptr<PeerConnection>> peers_to_ping;
        {
            std::lock_guard<std::mutex> lock(peers_mutex);
            for (auto& pair : active_peers) {
                peers_to_ping.push_back(pair.second);
            }
        }
        for (auto& peer : peers_to_ping) {
            if (peer->active) {
                std::vector<uint8_t> plain(1, 0x07); // Ping type
                try {
                    std::lock_guard<std::mutex> lock(peer->send_mutex);
                    net.sendData(peer->socket, peer->crypto->encrypt(plain));
                } catch (...) {}
            }
        }
    }
}

void acceptThread(int server_socket) {
    while (appRunning) {
        int client_socket = net.acceptConnection(server_socket);
        if (client_socket != -1) {
            auto peer = std::make_shared<PeerConnection>();
            peer->socket = client_socket;
            peer->crypto = std::make_unique<CryptoHandler>();
            
            if (performHandshake(client_socket, peer, false)) {
                NetworkManager::setSocketTimeout(client_socket, 60);
                std::lock_guard<std::mutex> lock(peers_mutex);
                active_peers[peer->peer_name] = peer;
                std::cout << "\n[System] Peer '" << peer->peer_name << "' connected!\n";
                std::cout << "[System] Safety Number: " << peer->crypto->getFingerprint() << "\n> ";
                std::cout.flush();
                
                std::thread r(receiveThread, peer);
                r.detach();
            } else {
                net.closeSocket(client_socket);
            }
        } else {
            if (appRunning) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }
}

int main(int argc, char* argv[]) {
#ifdef SIGPIPE
    signal(SIGPIPE, SIG_IGN);
#endif

    if (argc < 3) {
        std::cout << "Usage: " << argv[0] << " <my_name> <listen_port>\n";
        return 1;
    }

    my_name = argv[1];
    listen_port = std::stoi(argv[2]);

    server_sock_global = net.host(listen_port);
    if (server_sock_global == -1) {
        std::cout << "Failed to host on port " << listen_port << "\n";
        return 1;
    }

    std::thread at(acceptThread, server_sock_global);
    at.detach();

    std::thread pt(pingThread);
    pt.detach();

    std::cout << "Welcome " << my_name << "! You are a P2P node listening on port " << listen_port << ".\n";
    std::cout << "Commands:\n";
    std::cout << "  /connect <ip> <port>   - Connect to another node\n";
    std::cout << "  /list                  - Show connected peers\n";
    std::cout << "  /<name> <message>      - Send text to a peer\n";
    std::cout << "  /file <name> <path>    - Send a file to a peer\n";
    std::cout << "  /quit                  - Exit\n";

    std::string input;
    while (appRunning) {
        std::cout << "> ";
        std::cout.flush();
        if (!std::getline(std::cin, input)) break;
        
        while (!input.empty() && (input.back() == '\r' || input.back() == '\n' || input.back() == ' ')) input.pop_back();
        while (!input.empty() && (input.front() == ' ' || input.front() == '\t')) input.erase(0, 1);
        if (input.empty()) continue;

        if (input == "/quit" || input == "/exit") {
            appRunning = false;
            std::vector<uint8_t> plain(1, 0x06); // Disconnect
            {
                std::lock_guard<std::mutex> lock(peers_mutex);
                for (auto& pair : active_peers) {
                    try {
                        std::lock_guard<std::mutex> slock(pair.second->send_mutex);
                        net.sendData(pair.second->socket, pair.second->crypto->encrypt(plain));
                    } catch (...) {}
                }
            }
            break;
        }

        if (input.rfind("/connect ", 0) == 0) {
            std::stringstream ss(input.substr(9));
            std::string ip;
            int port;
            if (ss >> ip >> port) {
                std::cout << "[System] Connecting to " << ip << ":" << port << "...\n";
                int sock = net.connectTo(ip, port);
                if (sock != -1) {
                    auto peer = std::make_shared<PeerConnection>();
                    peer->socket = sock;
                    peer->crypto = std::make_unique<CryptoHandler>();
                    
                    if (performHandshake(sock, peer, true)) {
                        NetworkManager::setSocketTimeout(sock, 60);
                        std::lock_guard<std::mutex> lock(peers_mutex);
                        active_peers[peer->peer_name] = peer;
                        std::cout << "[System] Connected to peer '" << peer->peer_name << "'!\n";
                        std::cout << "[System] Safety Number: " << peer->crypto->getFingerprint() << "\n";
                        
                        std::thread r(receiveThread, peer);
                        r.detach();
                    } else {
                        std::cout << "[System] Handshake failed.\n";
                        net.closeSocket(sock);
                    }
                }
            } else {
                std::cout << "[System] Usage: /connect <ip> <port>\n";
            }
            continue;
        }

        if (input == "/list") {
            std::lock_guard<std::mutex> lock(peers_mutex);
            std::cout << "[System] Active Peers:\n";
            for (const auto& pair : active_peers) {
                std::cout << "  - " << pair.first << "\n";
            }
            if (active_peers.empty()) std::cout << "  (None)\n";
            continue;
        }

        if (input.rfind("/file ", 0) == 0) {
            std::stringstream ss(input.substr(6));
            std::string target_name;
            std::string path;
            ss >> target_name;
            std::getline(ss, path);
            
            while (!path.empty() && (path.front() == ' ' || path.front() == '\t' || path.front() == '"' || path.front() == '\'')) path.erase(0, 1);
            while (!path.empty() && (path.back() == '"' || path.back() == '\'')) path.pop_back();
            while (!path.empty() && (path.back() == ' ' || path.back() == '\t')) path.pop_back();

            std::shared_ptr<PeerConnection> target_peer;
            {
                std::lock_guard<std::mutex> lock(peers_mutex);
                if (active_peers.count(target_name)) target_peer = active_peers[target_name];
            }
            
            if (!target_peer) {
                std::cout << "[System] Peer '" << target_name << "' not found.\n";
                continue;
            }

            if (!std::filesystem::exists(path)) {
                std::cout << "[System] File not found: " << path << "\n";
                continue;
            }

            uint32_t size = std::filesystem::file_size(path);
            std::filesystem::path p(path);
            std::string name = p.filename().string();

            std::vector<uint8_t> plain(7 + name.size());
            plain[0] = 0x02;
            uint32_t s_n = htonl(size);
            std::memcpy(&plain[1], &s_n, 4);
            uint16_t len_n = htons(name.size());
            std::memcpy(&plain[5], &len_n, 2);
            std::memcpy(&plain[7], name.data(), name.size());

            target_peer->fileReqWait = true;
            try {
                {
                    std::lock_guard<std::mutex> lock(target_peer->send_mutex);
                    net.sendData(target_peer->socket, target_peer->crypto->encrypt(plain));
                }
                
                int timeouts = 150;
                while (target_peer->fileReqWait && timeouts > 0 && target_peer->active) {
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                    timeouts--;
                }
                
                if (!target_peer->fileReqWait && target_peer->active) {
                    std::cout << "[System] Uploading to " << target_name << ". Resuming from byte " << target_peer->resumeOffset.load() << "...\n";
                    std::thread t(sendFileWorker, path, target_peer->resumeOffset.load(), size, target_peer);
                    t.detach();
                } else {
                    target_peer->fileReqWait = false;
                    std::cout << "[System] File transfer request to " << target_name << " timed out or failed.\n";
                }
            } catch (...) {
                std::cout << "[System] Error initiating file transfer.\n";
            }
            continue;
        }

        if (input.front() == '/') {
            size_t space_pos = input.find(' ');
            if (space_pos != std::string::npos) {
                std::string target_name = input.substr(1, space_pos - 1);
                std::string msg = input.substr(space_pos + 1);
                
                std::shared_ptr<PeerConnection> target_peer;
                {
                    std::lock_guard<std::mutex> lock(peers_mutex);
                    if (active_peers.count(target_name)) target_peer = active_peers[target_name];
                }
                
                if (target_peer) {
                    packet_send_msg(target_peer, msg);
                } else {
                    std::cout << "[System] Peer '" << target_name << "' not found.\n";
                }
            } else {
                std::cout << "[System] Unknown command or bad syntax. Try /<name> <message>\n";
            }
            continue;
        }

        std::cout << "[System] You must use /<peer_name> <message> to chat. Use /list to see peers.\n";
    }

    net.closeSocket(server_sock_global);
    return 0;
}
