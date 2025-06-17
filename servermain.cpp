#include <iostream>
#include <thread>
#include <cstring>
#include <cstdlib>
#include <ctime>
#include <map>
#include <mutex>
#include <chrono>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>
#include "protocol.h"
#include "calcLib.h"

#define BUFFER_SIZE 1024
#define TIMEOUT_SEC 10
constexpr int ID_EXPIRATION_SECONDS = 10;  // IDs expire after 10 seconds

// Structure to store client assignment information
struct ClientAssignment {
    std::chrono::steady_clock::time_point timestamp;
    sockaddr_storage clientAddr;
    socklen_t clientAddrLen;
    calcProtocol assignment;
};

// Global map for storing client assignments
std::map<uint32_t, ClientAssignment> clientAssignments;
std::mutex mapMutex;  // Mutex to protect the map

// Forward declarations
void handleCalcMessage(int serverSocket, struct sockaddr_storage &clientAddr, socklen_t clientAddrLen, calcMessage *receivedMsg);
void handleCalcProtocol(int serverSocket, struct sockaddr_storage &clientAddr, socklen_t clientAddrLen, calcProtocol *clientMessage);
void cleanExpiredIDs();
uint32_t generateRandomID() { return rand(); }
bool compareSockaddr(const sockaddr_storage *a, const sockaddr_storage *b);
void sendVerificationResponse(int socket, const sockaddr_storage &addr, socklen_t addrLen, int status);
void sendErrorResponse(int socket, const sockaddr_storage &addr, socklen_t addrLen, int errorCode);
uint32_t mapOperationToArith(const std::string &operation);
int performCalculation(struct calcProtocol receivedData, int* intResult, double* floatResult);

// Clean expired IDs
void cleanExpiredIDs() {
    auto now = std::chrono::steady_clock::now();
    std::lock_guard<std::mutex> lock(mapMutex);
    for (auto it = clientAssignments.begin(); it != clientAssignments.end();) {
        if (std::chrono::duration_cast<std::chrono::seconds>(now - it->second.timestamp).count() > ID_EXPIRATION_SECONDS) {
            char clientIP[INET6_ADDRSTRLEN];
            if (it->second.clientAddr.ss_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)&it->second.clientAddr;
                inet_ntop(AF_INET, &s->sin_addr, clientIP, sizeof(clientIP));
            } else {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)&it->second.clientAddr;
                inet_ntop(AF_INET6, &s->sin6_addr, clientIP, sizeof(clientIP));
            }
            std::cout << "Expired ID " << it->first << " from " << clientIP << std::endl;
            it = clientAssignments.erase(it);
        } else {
            ++it;
        }
    }
}

// Compare two sockaddr_storage structures
bool compareSockaddr(const sockaddr_storage *a, const sockaddr_storage *b) {
    if (a->ss_family != b->ss_family) return false;
    
    if (a->ss_family == AF_INET) {
        struct sockaddr_in *a4 = (struct sockaddr_in *)a;
        struct sockaddr_in *b4 = (struct sockaddr_in *)b;
        return (a4->sin_port == b4->sin_port) && 
               (a4->sin_addr.s_addr == b4->sin_addr.s_addr);
    } else { // AF_INET6
        struct sockaddr_in6 *a6 = (struct sockaddr_in6 *)a;
        struct sockaddr_in6 *b6 = (struct sockaddr_in6 *)b;
        return (a6->sin6_port == b6->sin6_port) && 
               (memcmp(&a6->sin6_addr, &b6->sin6_addr, sizeof(a6->sin6_addr)) == 0);
    }
}

// Send verification response
void sendVerificationResponse(int socket, const sockaddr_storage &addr, socklen_t addrLen, int status) {
    calcMessage response{};
    response.type = htons(2);
    response.protocol = htons(17);
    response.major_version = htons(1);
    response.minor_version = htons(0);
    response.message = htonl(status);
    sendto(socket, &response, sizeof(response), 0, (struct sockaddr *)&addr, addrLen);
}

// Send error response
void sendErrorResponse(int socket, const sockaddr_storage &addr, socklen_t addrLen, int errorCode) {
    calcMessage response{};
    response.type = htons(2);
    response.protocol = htons(17);
    response.major_version = htons(1);
    response.minor_version = htons(0);
    response.message = htonl(errorCode);
    sendto(socket, &response, sizeof(response), 0, (struct sockaddr *)&addr, addrLen);
}

// Map operation string to arithmetic code
uint32_t mapOperationToArith(const std::string &operation) {
    if (operation == "add") return 1;
    if (operation == "sub") return 2;
    if (operation == "mul") return 3;
    if (operation == "div") return 4;
    if (operation == "fadd") return 5;
    if (operation == "fsub") return 6;
    if (operation == "fmul") return 7;
    if (operation == "fdiv") return 8;
    return 0;
}

// Perform calculation based on received data
int performCalculation(struct calcProtocol receivedData, int* intResult, double* floatResult) {
    int value1 = ntohl(receivedData.inValue1);
    int value2 = ntohl(receivedData.inValue2);
    double dvalue1 = receivedData.flValue1;
    double dvalue2 = receivedData.flValue2;

    switch (ntohl(receivedData.arith)) {
        case 1:  // Add
            *intResult = value1 + value2;
            break;
        case 2:  // Subtract
            *intResult = value1 - value2;
            break;
        case 3:  // Multiply
            *intResult = value1 * value2;
            break;
        case 4:  // Divide
            if (value2 == 0) return 2;  // Division by zero
            *intResult = value1 / value2;
            break;
        case 5:  // Floating-point Add
            *floatResult = dvalue1 + dvalue2;
            break;
        case 6:  // Floating-point Subtract
            *floatResult = dvalue1 - dvalue2;
            break;
        case 7:  // Floating-point Multiply
            *floatResult = dvalue1 * dvalue2;
            break;
        case 8:  // Floating-point Divide
            if (dvalue2 == 0.0) return 2;  // Division by zero
            *floatResult = dvalue1 / dvalue2;
            break;
    }

    if (ntohl(receivedData.arith) <= 4) {
        return (ntohl(receivedData.inResult) == *intResult) ? 1 : 2;
    } else {
        return (receivedData.flResult == *floatResult) ? 1 : 2;
    }
}

// Thread function for handling calcMessage
void handleCalcMessageThread(int serverSocket, struct sockaddr_storage clientAddr, socklen_t clientAddrLen, calcMessage *receivedMsg) {
    handleCalcMessage(serverSocket, clientAddr, clientAddrLen, receivedMsg);
    delete receivedMsg;
}

// Thread function for handling calcProtocol
void handleCalcProtocolThread(int serverSocket, struct sockaddr_storage clientAddr, socklen_t clientAddrLen, calcProtocol *clientMessage) {
    handleCalcProtocol(serverSocket, clientAddr, clientAddrLen, clientMessage);
    delete clientMessage;
}

// Handle calcMessage
void handleCalcMessage(int serverSocket, struct sockaddr_storage &clientAddr, socklen_t clientAddrLen, calcMessage *receivedMsg) {
    cleanExpiredIDs();

    // Get client IP and port for logging
    char clientIP[INET6_ADDRSTRLEN];
    int clientPort;
    if (clientAddr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
        inet_ntop(AF_INET, &s->sin_addr, clientIP, sizeof(clientIP));
        clientPort = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&clientAddr;
        inet_ntop(AF_INET6, &s->sin6_addr, clientIP, sizeof(clientIP));
        clientPort = ntohs(s->sin6_port);
    }
    std::cout << "Received calcMessage from " << clientIP << ":" << clientPort << std::endl;

    // Validate message format
    if (ntohs(receivedMsg->type) != 22 || ntohl(receivedMsg->message) != 0 || 
        ntohs(receivedMsg->protocol) != 17 || ntohs(receivedMsg->major_version) != 1 || 
        ntohs(receivedMsg->minor_version) != 0) {
        
        std::cout << "Invalid calcMessage format from " << clientIP << ":" << clientPort << std::endl;
        sendErrorResponse(serverSocket, clientAddr, clientAddrLen, 2);
        return;
    }

    // Prepare response
    calcProtocol response{};
    response.type = htons(1);
    response.major_version = htons(1);
    response.minor_version = htons(0);
    uint32_t generatedID = generateRandomID();
    response.id = htonl(generatedID);

    // Generate random operation and values
    char *operation = randomType();
    response.arith = htonl(mapOperationToArith(operation));

    if (operation[0] == 'f') {
        response.flValue1 = randomFloat();
        response.flValue2 = randomFloat();
    } else {
        response.inValue1 = htonl(randomInt());
        response.inValue2 = htonl(randomInt());
    }

    // Store the assignment
    {
        std::lock_guard<std::mutex> lock(mapMutex);
        ClientAssignment assignment;
        assignment.timestamp = std::chrono::steady_clock::now();
        assignment.clientAddr = clientAddr;
        assignment.clientAddrLen = clientAddrLen;
        assignment.assignment = response;
        clientAssignments[generatedID] = assignment;
    }

    std::cout << "Assigned ID " << generatedID << " to " << clientIP << ":" << clientPort 
              << " with operation " << operation << std::endl;

    sendto(serverSocket, &response, sizeof(response), 0, (struct sockaddr *)&clientAddr, clientAddrLen);
}

// Handle calcProtocol
void handleCalcProtocol(int serverSocket, struct sockaddr_storage &clientAddr, socklen_t clientAddrLen, calcProtocol *clientMessage) {
    uint32_t clientID = ntohl(clientMessage->id);

    // Get client IP and port for logging
    char clientIP[INET6_ADDRSTRLEN];
    int clientPort;
    if (clientAddr.ss_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
        inet_ntop(AF_INET, &s->sin_addr, clientIP, sizeof(clientIP));
        clientPort = ntohs(s->sin_port);
    } else {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)&clientAddr;
        inet_ntop(AF_INET6, &s->sin6_addr, clientIP, sizeof(clientIP));
        clientPort = ntohs(s->sin6_port);
    }
    std::cout << "Received calcProtocol from " << clientIP << ":" << clientPort 
              << " with ID " << clientID << std::endl;

    // Lock the map for thread-safe access
    std::lock_guard<std::mutex> lock(mapMutex);

    auto it = clientAssignments.find(clientID);
    if (it != clientAssignments.end()) {
        auto now = std::chrono::steady_clock::now();
        auto timeDiff = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.timestamp).count();

        if (timeDiff < ID_EXPIRATION_SECONDS) {
            // Verify client identity
            if (!compareSockaddr(&clientAddr, &it->second.clientAddr)) {
                std::cout << "Client identity mismatch for ID " << clientID << std::endl;
                sendErrorResponse(serverSocket, clientAddr, clientAddrLen, 2);
                return;
            }

            // Verify operation matches
            if (ntohl(clientMessage->arith) != ntohl(it->second.assignment.arith)) {
                std::cout << "Operation mismatch for ID " << clientID << std::endl;
                sendErrorResponse(serverSocket, clientAddr, clientAddrLen, 2);
                return;
            }

            // Update timestamp
            it->second.timestamp = now;

            // Perform calculation and verify result
            int intResult;
            double floatResult;
            int resultStatus = performCalculation(*clientMessage, &intResult, &floatResult);

            std::cout << "Result for ID " << clientID << " from " << clientIP << ":" << clientPort 
                      << " is " << (resultStatus == 1 ? "correct" : "incorrect") << std::endl;

            sendVerificationResponse(serverSocket, clientAddr, clientAddrLen, resultStatus);
            return;
        }
    }

    // ID not found or expired
    std::cout << "Invalid or expired ID " << clientID << " from " << clientIP << ":" << clientPort << std::endl;
    sendErrorResponse(serverSocket, clientAddr, clientAddrLen, 2);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0] << " <IP:Port>\n";
        return 1;
    }

    std::string ipPort(argv[1]);
    size_t colonPos = ipPort.find(":");
    if (colonPos == std::string::npos) {
        std::cerr << "Invalid IP:Port format.\n";
        return 1;
    }

    std::string ip = ipPort.substr(0, colonPos);
    std::string portStr = ipPort.substr(colonPos + 1);
    int port = std::stoi(portStr);

    struct addrinfo hints{}, *res;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    if (getaddrinfo(ip.c_str(), portStr.c_str(), &hints, &res) != 0) {
        std::cerr << "Error resolving address\n";
        return 1;
    }

    int serverSocket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (serverSocket == -1) {
        perror("Socket creation failed");
        return 1;
    }

    if (bind(serverSocket, res->ai_addr, res->ai_addrlen) == -1) {
        perror("Bind failed");
        close(serverSocket);
        return 1;
    }

    std::cout << "UDP Server listening on " << ip << ":" << port << "\n";

    struct timeval timeout{};
    timeout.tv_sec = TIMEOUT_SEC;
    timeout.tv_usec = 0;
    setsockopt(serverSocket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));

    char buffer[BUFFER_SIZE] = {0};
    sockaddr_storage clientAddr{};
    socklen_t clientAddrLen = sizeof(clientAddr);

    initCalcLib();
    srand(time(nullptr)); // Seed random number generator

    while (true) {
        std::cout << "Waiting for client data..." << std::endl;

        int bytesReceived = recvfrom(serverSocket, buffer, BUFFER_SIZE, 0,
                                     (struct sockaddr *)&clientAddr, &clientAddrLen);
        if (bytesReceived == -1) {
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                cleanExpiredIDs();
                continue;
            }
            perror("recvfrom failed");
            continue;
        }

        // Log basic info about received message
        char clientIP[INET6_ADDRSTRLEN];
        int clientPort;
        if (clientAddr.ss_family == AF_INET) {
            struct sockaddr_in *s = (struct sockaddr_in *)&clientAddr;
            inet_ntop(AF_INET, &s->sin_addr, clientIP, sizeof(clientIP));
            clientPort = ntohs(s->sin_port);
        } else {
            struct sockaddr_in6 *s = (struct sockaddr_in6 *)&clientAddr;
            inet_ntop(AF_INET6, &s->sin6_addr, clientIP, sizeof(clientIP));
            clientPort = ntohs(s->sin6_port);
        }

        if (bytesReceived == sizeof(calcProtocol)) {
            std::cout << "Received calcProtocol from " << clientIP << ":" << clientPort << std::endl;
            calcProtocol *clientMessage = new calcProtocol();
            std::memcpy(clientMessage, buffer, sizeof(calcProtocol));
            std::thread protocolThread(handleCalcProtocolThread, serverSocket, clientAddr, clientAddrLen, clientMessage);
            protocolThread.detach();
        } else if (bytesReceived == sizeof(calcMessage)) {
            std::cout << "Received calcMessage from " << clientIP << ":" << clientPort << std::endl;
            calcMessage *msg = new calcMessage();
            std::memcpy(msg, buffer, sizeof(calcMessage));
            std::thread messageThread(handleCalcMessageThread, serverSocket, clientAddr, clientAddrLen, msg);
            messageThread.detach();
        } else {
            std::cerr << "Unknown message format (" << bytesReceived << " bytes) from " 
                      << clientIP << ":" << clientPort << std::endl;
        }
    }

    close(serverSocket);
    return 0;
}
