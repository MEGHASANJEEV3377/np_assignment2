#include <iostream>
#include <vector>
#include <string>
#include <cstdlib>
#include <cstring>
#include <netdb.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cerrno>
#include <cstdio>
#include <calcLib.h>
#include <sstream>
#include <cstdint>
#include <iomanip>
#include "protocol.h"

#define DEBUG

std::vector<std::string> splitString(const std::string& str, const std::string& delimiter);

void initializeSocket(const std::string& ip, int port, struct sockaddr_storage* server_addr, socklen_t* addr_len, int* ip_version);

struct calcMessage receiveCalcMessage(int socket_fd, int* bytes_transferred, struct sockaddr_storage* server_addr, socklen_t addr_len);

struct calcProtocol receiveCalcProtocol(int socket_fd, int* bytes_transferred, struct sockaddr_storage* server_addr, socklen_t addr_len);

struct calcProtocol performCalculation(struct calcProtocol receivedData, int* intResult, double* floatResult, int* calculationStatus);

void sendInitialMessage(int socket_fd, struct calcMessage initialMsg, struct sockaddr_storage* server_addr, socklen_t addr_len, int* bytes_transferred);

void sendProtocolMessage(int socket_fd, struct calcProtocol protocolMsg, struct sockaddr_storage* server_addr, socklen_t addr_len, int* bytes_transferred);

struct calcMessage initialCalcMessage;

int main(int argc, char* argv[]) {
    initCalcLib();

    initialCalcMessage.type = htons(22);
    initialCalcMessage.message = htons(0);
    initialCalcMessage.protocol = htons(17);
    initialCalcMessage.major_version = htons(1);
    initialCalcMessage.minor_version = htons(0);

    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IP:PORT>" << std::endl;
        return 1;
    }

    std::string delimiter = ":";
    std::vector<std::string> outputParts = splitString(argv[1], delimiter);

    if (outputParts.size() != 2) {
        std::cerr << "Invalid IP:PORT format" << std::endl;
        return 1;
    }

    std::string ipAddress = outputParts[0];
    int portNumber = std::stoi(outputParts[1]);

    std::cout << "HOST " << ipAddress << ", and port " << portNumber << std::endl;

    struct sockaddr_storage server_addr;
    socklen_t addr_len;
    int ip_version;

    // Dynamically determine address family and initialize the server address
    initializeSocket(ipAddress, portNumber, &server_addr, &addr_len, &ip_version);

    // Create socket using the determined address family
    int socket_fd = socket(ip_version, SOCK_DGRAM, IPPROTO_UDP);
    if (socket_fd < 0) {
        perror("Error in socket creation");
        return 1;
    }
#ifdef DEBUG
    std::cout << "[DEBUG] Socket created successfully for " << (ip_version == AF_INET ? "IPv4" : "IPv6") << "." << std::endl;
#endif

    struct timeval timeout = {2, 0};
    if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout)) < 0) {
        perror("Error setting timeout");
        close(socket_fd);
        return 1;
    }
#ifdef DEBUG
    std::cout << "[DEBUG] Timeout set to 2 seconds." << std::endl;
#endif

    int sent_recv_bytes;
    struct calcProtocol receivedMessage, responseMessage;

    sendInitialMessage(socket_fd, initialCalcMessage, &server_addr, addr_len, &sent_recv_bytes);

#ifdef DEBUG
    std::cout << "[DEBUG] Sent initial message to server." << std::endl;
#endif

    receivedMessage = receiveCalcProtocol(socket_fd, &sent_recv_bytes, &server_addr, addr_len);

    if (sent_recv_bytes < 0) {
        int retry_count = 2;
        while (retry_count--) {
#ifdef DEBUG
            std::cout << "[DEBUG] Retrying to send initial message. Retries left: " << retry_count << std::endl;
#endif
            sendInitialMessage(socket_fd, initialCalcMessage, &server_addr, addr_len, &sent_recv_bytes);
            receivedMessage = receiveCalcProtocol(socket_fd, &sent_recv_bytes, &server_addr, addr_len);
            if (sent_recv_bytes >= 0) break;
        }
        if (sent_recv_bytes < 0) {
            std::cerr << "Unable to connect with the server" << std::endl;
            close(socket_fd);
            return 1;
        }
    }

    int intResult;
    double floatResult;
    int calcStatus;

    responseMessage = performCalculation(receivedMessage, &intResult, &floatResult, &calcStatus);

#ifdef DEBUG
    std::cout << "[DEBUG] Calculated response. Sending result to server." << std::endl;
#endif

    sendProtocolMessage(socket_fd, responseMessage, &server_addr, addr_len, &sent_recv_bytes);

#ifdef DEBUG
    std::cout << "[DEBUG] Sent result message to server." << std::endl;
#endif

    struct calcMessage confirmationMessage = receiveCalcMessage(socket_fd, &sent_recv_bytes, &server_addr, addr_len);
    if (ntohl(confirmationMessage.message) == 1) {
        if (calcStatus == 1) {
            std::cout << "OK (myresult=" << intResult << ")" << std::endl;
        } else if (calcStatus == 2) {
            std::cout << "OK (myresult=" << floatResult << ")" << std::endl;
        }
    } else {
        std::cout << "Server not OK" << std::endl;
    }

#ifdef DEBUG
    std::cout << "[DEBUG] Final response received from server." << std::endl;
#endif

    close(socket_fd);
    return 0;
}

void initializeSocket(const std::string& ip, int port, sockaddr_storage* server_addr, socklen_t* addr_len, int* ip_version) {
    struct addrinfo hints{}, *res, *p;
    hints.ai_family = AF_UNSPEC;  // Allow both IPv4 and IPv6
    hints.ai_socktype = SOCK_DGRAM;  // Datagram socket for UDP

    if (getaddrinfo(ip.c_str(), std::to_string(port).c_str(), &hints, &res) != 0) {
        std::cerr << "Error in getaddrinfo" << std::endl;
        std::exit(EXIT_FAILURE);
    }

    for (p = res; p != nullptr; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            memcpy(server_addr, p->ai_addr, sizeof(struct sockaddr_in));
            *addr_len = sizeof(struct sockaddr_in);
            *ip_version = AF_INET;
            break;
        } else if (p->ai_family == AF_INET6) {
            memcpy(server_addr, p->ai_addr, sizeof(struct sockaddr_in6));
            *addr_len = sizeof(struct sockaddr_in6);
            *ip_version = AF_INET6;
            break;
        }
    }

    freeaddrinfo(res);

    if (*ip_version == 0) {
        std::cerr << "Unable to resolve address" << std::endl;
        std::exit(EXIT_FAILURE);
    }
#ifdef DEBUG
    std::cout << "[DEBUG] Address resolved to " << (*ip_version == AF_INET ? "IPv4" : "IPv6") << "." << std::endl;
#endif
}

std::vector<std::string> splitString(const std::string& str, const std::string& delimiter) {
    std::vector<std::string> result;
    size_t pos_start = 0, pos_end, delim_len = delimiter.length();
    while ((pos_end = str.find(delimiter, pos_start)) != std::string::npos) {
        result.emplace_back(str.substr(pos_start, pos_end - pos_start));
        pos_start = pos_end + delim_len;
    }
    result.emplace_back(str.substr(pos_start));
    return result;
}

void sendInitialMessage(int socket_fd, struct calcMessage initialMsg, struct sockaddr_storage* server_addr, socklen_t addr_len, int* bytes_transferred) {
    *bytes_transferred = sendto(socket_fd, &initialMsg, sizeof(struct calcMessage), 0, (struct sockaddr*)server_addr, addr_len);
#ifdef DEBUG
    std::cout << "[DEBUG] Sent initial message (type=" << ntohs(initialMsg.type) << ")." << std::endl;
#endif
}

void sendProtocolMessage(int socket_fd, struct calcProtocol protocolMsg, struct sockaddr_storage* server_addr, socklen_t addr_len, int* bytes_transferred) {
    *bytes_transferred = sendto(socket_fd, &protocolMsg, sizeof(struct calcProtocol), 0, (struct sockaddr*)server_addr, addr_len);
#ifdef DEBUG
    std::cout << "[DEBUG] Sent protocol message with result." << std::endl;
#endif
}

struct calcMessage receiveCalcMessage(int socket_fd, int* bytes_transferred, struct sockaddr_storage* server_addr, socklen_t addr_len) {
    struct calcMessage receivedMsg;
    *bytes_transferred = recvfrom(socket_fd, &receivedMsg, sizeof(struct calcMessage), 0, (struct sockaddr*)server_addr, &addr_len);
#ifdef DEBUG
    std::cout << "[DEBUG] Received calcMessage with message=" << ntohl(receivedMsg.message) << "." << std::endl;
#endif
    return receivedMsg;
}

struct calcProtocol receiveCalcProtocol(int socket_fd, int* bytes_transferred, struct sockaddr_storage* server_addr, socklen_t addr_len) {
    struct calcProtocol receivedMsg;
    *bytes_transferred = recvfrom(socket_fd, &receivedMsg, sizeof(struct calcProtocol), 0, (struct sockaddr*)server_addr, &addr_len);
#ifdef DEBUG
    std::cout << "[DEBUG] Received calcProtocol with arith=" << ntohl(receivedMsg.arith) << "." << std::endl;
#endif
    return receivedMsg;
}

struct calcProtocol performCalculation(struct calcProtocol receivedData, int* intResult, double* floatResult, int* calculationStatus) {
    int value1 = ntohl(receivedData.inValue1);
    int value2 = ntohl(receivedData.inValue2);
    double dvalue1 = receivedData.flValue1;
    double dvalue2 = receivedData.flValue2;

    switch (ntohl(receivedData.arith)) {
        case 1:
            *intResult = value1 + value2;
            *calculationStatus = 1;
            receivedData.inResult = htonl(*intResult);
            break;
        case 2:
            *intResult = value1 - value2;
            *calculationStatus = 1;
            receivedData.inResult = htonl(*intResult);
            break;
        case 3:
            *intResult = value1 * value2;
            *calculationStatus = 1;
            receivedData.inResult = htonl(*intResult);
            break;
        case 4:
            *intResult = value1 / value2;
            *calculationStatus = 1;
            receivedData.inResult = htonl(*intResult);
            break;
        case 5:
            *floatResult = dvalue1 + dvalue2;
            *calculationStatus = 2;
            receivedData.flResult = *floatResult;
            break;
        case 6:
            *floatResult = dvalue1 - dvalue2;
            *calculationStatus = 2;
            receivedData.flResult = *floatResult;
            break;
        case 7:
            *floatResult = dvalue1 * dvalue2;
            *calculationStatus = 2;
            receivedData.flResult = *floatResult;
            break;
        case 8:
            *floatResult = dvalue1 / dvalue2;
            *calculationStatus = 2;
            receivedData.flResult = *floatResult;
            break;
    }

    return receivedData;
}
