#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <vector>
#include <string>
#include <sstream>

// Structure to hold parsed DNS header values
struct DnsHeader {
    uint16_t id;
    bool qr;
    uint8_t opcode;
    bool aa;
    bool tc;
    bool rd;
    bool ra;
    uint8_t z;
    uint8_t rcode;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};

// Structure to hold a DNS question
struct DnsQuestion {
    std::vector<unsigned char> name; // Uncompressed name bytes
    uint16_t type;
    uint16_t class_;
};

// Structure to hold the IP and port of the DNS resolver
struct ResolverAddress {
    std::string ip;
    int port;
};

// Parse the DNS header from a buffer
DnsHeader parseDnsHeader(const unsigned char* buffer) {
    DnsHeader header;
    
    // Extract ID (first 2 bytes)
    header.id = (buffer[0] << 8) | buffer[1];
    
    // Extract flags from byte 2
    header.qr = (buffer[2] & 0x80) >> 7;
    header.opcode = (buffer[2] & 0x78) >> 3;
    header.aa = (buffer[2] & 0x04) >> 2;
    header.tc = (buffer[2] & 0x02) >> 1;
    header.rd = (buffer[2] & 0x01);
    
    // Extract flags from byte 3
    header.ra = (buffer[3] & 0x80) >> 7;
    header.z = (buffer[3] & 0x70) >> 4;
    header.rcode = (buffer[3] & 0x0F);
    
    // Extract record counts
    header.qdcount = (buffer[4] << 8) | buffer[5];
    header.ancount = (buffer[6] << 8) | buffer[7];
    header.nscount = (buffer[8] << 8) | buffer[9];
    header.arcount = (buffer[10] << 8) | buffer[11];
    
    return header;
}

// Parse a DNS domain name from a buffer, handling compression
std::vector<unsigned char> parseDnsNameUncompressed(const unsigned char* buffer, int offset, int& endOffset, const unsigned char* packetStart) {
    std::vector<unsigned char> uncompressedName;
    int pos = offset;
    bool jumped = false;
    int nextPos = 0;
    
    // Maximum number of jumps to prevent infinite loops due to malformed packets
    int maxJumps = 10;
    int jumps = 0;
    
    while (true) {
        if (jumps++ > maxJumps) {
            std::cerr << "Too many compression jumps, possibly malformed packet" << std::endl;
            break;
        }
        
        // Check if this is the end of the name
        if (buffer[pos] == 0) {
            uncompressedName.push_back(0); // Add the terminating null byte
            if (!jumped) {
                pos++; // Only advance the position if we haven't jumped
            }
            break;
        }
        
        // Check for a compression pointer
        if ((buffer[pos] & 0xC0) == 0xC0) {
            // It's a compression pointer
            if (!jumped) {
                // Save the position after the jump for the first time
                nextPos = pos + 2;
            }
            
            // Get the offset from the compression pointer (14 bits)
            int jumpOffset = ((buffer[pos] & 0x3F) << 8) | buffer[pos + 1];
            pos = jumpOffset;
            jumped = true;
            
            // After a jump, we're now pointing to the start of a new label sequence
            buffer = packetStart; // Ensure we're using the start of the packet for offset calculation
        } else {
            // It's a regular label
            uint8_t labelLength = buffer[pos];
            uncompressedName.push_back(labelLength); // Add the length byte
            pos++;
            
            // Add each character of the label
            for (int i = 0; i < labelLength; i++) {
                uncompressedName.push_back(buffer[pos]);
                pos++;
            }
        }
    }
    
    // Set the end offset
    if (jumped) {
        endOffset = nextPos; // If we jumped, the end is after the last compression pointer
    } else {
        endOffset = pos; // Otherwise, it's wherever we ended up
    }
    
    return uncompressedName;
}

// Parse a DNS question from a buffer, handling compression
DnsQuestion parseDnsQuestion(const unsigned char* buffer, int offset, int& endOffset, const unsigned char* packetStart) {
    DnsQuestion question;
    
    // Parse the name with compression handling
    question.name = parseDnsNameUncompressed(buffer, offset, offset, packetStart);
    
    // Extract type (2 bytes)
    question.type = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    
    // Extract class (2 bytes)
    question.class_ = (buffer[offset] << 8) | buffer[offset + 1];
    offset += 2;
    
    endOffset = offset;
    return question;
}

// Create a DNS packet with a single question, preserving request flags
std::vector<unsigned char> createDnsQuery(uint16_t id, const DnsHeader& requestHeader, const DnsQuestion& question) {
    std::vector<unsigned char> query(512, 0); // Initialize with zeros, standard DNS size
    
    // Header (12 bytes)
    // ID
    query[0] = (id >> 8) & 0xFF;
    query[1] = id & 0xFF;
    
    // Flags - preserve OPCODE and RD from the original request
    query[2] = 0;
    query[2] |= ((requestHeader.opcode & 0x0F) << 3); // Set OPCODE from request
    query[2] |= (requestHeader.rd & 0x01);            // Set RD from request
    query[3] = 0x00; // All other flags 0
    
    // QDCOUNT = 1
    query[4] = 0x00;
    query[5] = 0x01;
    
    // ANCOUNT = 0
    query[6] = 0x00;
    query[7] = 0x00;
    
    // NSCOUNT = 0
    query[8] = 0x00;
    query[9] = 0x00;
    
    // ARCOUNT = 0
    query[10] = 0x00;
    query[11] = 0x00;
    
    // Add the question
    int offset = 12;
    
    // Add the name
    for (unsigned char byte : question.name) {
        query[offset++] = byte;
    }
    
    // Add the type
    query[offset++] = (question.type >> 8) & 0xFF;
    query[offset++] = question.type & 0xFF;
    
    // Add the class
    query[offset++] = (question.class_ >> 8) & 0xFF;
    query[offset++] = question.class_ & 0xFF;
    
    // Resize the vector to the actual size
    query.resize(offset);
    
    return query;
}

// Forward a DNS query to a resolver and get the response
std::vector<unsigned char> forwardDnsQuery(const std::vector<unsigned char>& query, const ResolverAddress& resolver) {
    std::vector<unsigned char> response(512, 0);
    
    // Create a socket for the resolver
    int resolverSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (resolverSocket == -1) {
        std::cerr << "Resolver socket creation failed: " << strerror(errno) << std::endl;
        return response;
    }
    
    // Set up the resolver address
    sockaddr_in resolverAddr = {
        .sin_family = AF_INET,
        .sin_port = htons(resolver.port),
    };
    
    if (inet_pton(AF_INET, resolver.ip.c_str(), &resolverAddr.sin_addr) <= 0) {
        std::cerr << "Invalid resolver IP address: " << resolver.ip << std::endl;
        close(resolverSocket);
        return response;
    }
    
    // Set a timeout for the resolver socket
    struct timeval tv;
    tv.tv_sec = 5;  // 5 seconds timeout
    tv.tv_usec = 0;
    if (setsockopt(resolverSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        std::cerr << "Setting socket timeout failed: " << strerror(errno) << std::endl;
        close(resolverSocket);
        return response;
    }
    
    // Send the query to the resolver
    if (sendto(resolverSocket, query.data(), query.size(), 0,
               reinterpret_cast<struct sockaddr*>(&resolverAddr), sizeof(resolverAddr)) == -1) {
        std::cerr << "Failed to send query to resolver: " << strerror(errno) << std::endl;
        close(resolverSocket);
        return response;
    }
    
    // Receive the response from the resolver
    sockaddr_in fromAddr;
    socklen_t fromAddrLen = sizeof(fromAddr);
    int bytesRead = recvfrom(resolverSocket, response.data(), response.size(), 0,
                            reinterpret_cast<struct sockaddr*>(&fromAddr), &fromAddrLen);
    
    if (bytesRead <= 0) {
        std::cerr << "Failed to receive response from resolver: " << strerror(errno) << std::endl;
        close(resolverSocket);
        return response;
    }
    
    // Resize the response to the actual size
    response.resize(bytesRead);
    
    close(resolverSocket);
    return response;
}

// Create a DNS response by merging multiple responses
std::vector<unsigned char> mergeDnsResponses(uint16_t originalId, const DnsHeader& requestHeader,
                                            const std::vector<DnsQuestion>& questions, 
                                            const std::vector<std::vector<unsigned char>>& responses) {
    std::vector<unsigned char> mergedResponse(512, 0);
    
    // Set up the header (12 bytes)
    // ID - use the original ID from the client query
    mergedResponse[0] = (originalId >> 8) & 0xFF;
    mergedResponse[1] = originalId & 0xFF;
    
    // Flags - preserve QR=1 (response) and OPCODE from original request
    mergedResponse[2] = 0x80; // Set QR=1 (response)
    mergedResponse[2] |= ((requestHeader.opcode & 0x0F) << 3); // Preserve OPCODE from request
    mergedResponse[2] |= (0 << 2); // AA=0
    mergedResponse[2] |= (0 << 1); // TC=0
    mergedResponse[2] |= (requestHeader.rd & 0x01); // Preserve RD from request
    
    // Only copy RA, Z, and RCODE from the first response
    mergedResponse[3] = responses[0][3];
    
    // Set QDCOUNT to the number of questions
    uint16_t qdcount = questions.size();
    mergedResponse[4] = (qdcount >> 8) & 0xFF;
    mergedResponse[5] = qdcount & 0xFF;
    
    // Count the total answers
    uint16_t ancount = 0;
    for (const auto& response : responses) {
        ancount += (response[6] << 8) | response[7];
    }
    
    // Set ANCOUNT
    mergedResponse[6] = (ancount >> 8) & 0xFF;
    mergedResponse[7] = ancount & 0xFF;
    
    // Set NSCOUNT and ARCOUNT to 0
    mergedResponse[8] = 0x00;
    mergedResponse[9] = 0x00;
    mergedResponse[10] = 0x00;
    mergedResponse[11] = 0x00;
    
    // Add all questions
    int offset = 12;
    for (const auto& question : questions) {
        // Add the name
        for (unsigned char byte : question.name) {
            mergedResponse[offset++] = byte;
        }
        
        // Add the type
        mergedResponse[offset++] = (question.type >> 8) & 0xFF;
        mergedResponse[offset++] = question.type & 0xFF;
        
        // Add the class
        mergedResponse[offset++] = (question.class_ >> 8) & 0xFF;
        mergedResponse[offset++] = question.class_ & 0xFF;
    }
    
    // Add all answers from the responses
    for (int i = 0; i < responses.size(); i++) {
        const auto& response = responses[i];
        
        // Parse the response header
        DnsHeader header = parseDnsHeader(response.data());
        
        // Skip the header and the question section to get to the answer section
        int answerOffset = 12; // Skip header
        
        // Skip question section
        int tempOffset;
        DnsQuestion question = parseDnsQuestion(response.data(), answerOffset, tempOffset, response.data());
        answerOffset = tempOffset;
        
        // Copy the answer section
        int answerCount = (response[6] << 8) | response[7];
        for (int j = 0; j < answerCount; j++) {
            // Find the end of the answer by parsing it
            // For A records, we know the answer size is fixed:
            // - Name: variable (parsed)
            // - Type: 2 bytes
            // - Class: 2 bytes
            // - TTL: 4 bytes
            // - Data length: 2 bytes
            // - Data: Data length bytes (4 for A records)
            
            // Copy the name
            std::vector<unsigned char> name = parseDnsNameUncompressed(response.data(), answerOffset, tempOffset, response.data());
            for (unsigned char byte : name) {
                mergedResponse[offset++] = byte;
            }
            answerOffset = tempOffset;
            
            // Copy the rest of the answer fields (type, class, TTL, length, data)
            // Type (2 bytes)
            mergedResponse[offset++] = response[answerOffset];
            mergedResponse[offset++] = response[answerOffset + 1];
            
            // Class (2 bytes)
            mergedResponse[offset++] = response[answerOffset + 2];
            mergedResponse[offset++] = response[answerOffset + 3];
            
            // TTL (4 bytes)
            mergedResponse[offset++] = response[answerOffset + 4];
            mergedResponse[offset++] = response[answerOffset + 5];
            mergedResponse[offset++] = response[answerOffset + 6];
            mergedResponse[offset++] = response[answerOffset + 7];
            
            // Data length (2 bytes)
            uint16_t dataLength = (response[answerOffset + 8] << 8) | response[answerOffset + 9];
            mergedResponse[offset++] = response[answerOffset + 8];
            mergedResponse[offset++] = response[answerOffset + 9];
            
            // Data (dataLength bytes)
            for (int k = 0; k < dataLength; k++) {
                mergedResponse[offset++] = response[answerOffset + 10 + k];
            }
            
            // Move to the next answer
            answerOffset += 10 + dataLength;
        }
    }
    
    // Resize the response to the actual size
    mergedResponse.resize(offset);
    
    return mergedResponse;
}

// Parse the resolver address from the command line argument
ResolverAddress parseResolverAddress(const std::string& arg) {
    ResolverAddress resolver;
    
    size_t colonPos = arg.find(':');
    if (colonPos == std::string::npos) {
        // No port specified, use default port 53
        resolver.ip = arg;
        resolver.port = 53;
    } else {
        resolver.ip = arg.substr(0, colonPos);
        std::string portStr = arg.substr(colonPos + 1);
        resolver.port = std::stoi(portStr);
    }
    
    return resolver;
}

// Debug function to print DNS header fields
void printDnsHeader(const DnsHeader& header) {
    std::cout << "DNS Header:" << std::endl;
    std::cout << "  ID: 0x" << std::hex << header.id << std::dec << std::endl;
    std::cout << "  QR: " << (header.qr ? "Response" : "Query") << std::endl;
    std::cout << "  OPCODE: " << static_cast<int>(header.opcode) << std::endl;
    std::cout << "  AA: " << (header.aa ? "Yes" : "No") << std::endl;
    std::cout << "  TC: " << (header.tc ? "Yes" : "No") << std::endl;
    std::cout << "  RD: " << (header.rd ? "Yes" : "No") << std::endl;
    std::cout << "  RA: " << (header.ra ? "Yes" : "No") << std::endl;
    std::cout << "  Z: " << static_cast<int>(header.z) << std::endl;
    std::cout << "  RCODE: " << static_cast<int>(header.rcode) << std::endl;
    std::cout << "  QDCOUNT: " << header.qdcount << std::endl;
    std::cout << "  ANCOUNT: " << header.ancount << std::endl;
    std::cout << "  NSCOUNT: " << header.nscount << std::endl;
    std::cout << "  ARCOUNT: " << header.arcount << std::endl;
}

// Debug function to print a DNS question
void printDnsQuestion(const DnsQuestion& question) {
    std::cout << "DNS Question:" << std::endl;
    
    // Print name (for debugging)
    std::cout << "  Name (hex): ";
    for (unsigned char byte : question.name) {
        std::cout << std::hex << static_cast<int>(byte) << " ";
    }
    std::cout << std::dec << std::endl;
    
    // Try to parse and print domain name
    std::string domainName;
    int i = 0;
    while (i < question.name.size() && question.name[i] != 0) {
        int labelLength = question.name[i++];
        for (int j = 0; j < labelLength && i < question.name.size(); j++) {
            domainName += static_cast<char>(question.name[i++]);
        }
        if (i < question.name.size() && question.name[i] != 0) {
            domainName += ".";
        }
    }
    std::cout << "  Domain: " << domainName << std::endl;
    
    std::cout << "  Type: " << question.type << std::endl;
    std::cout << "  Class: " << question.class_ << std::endl;
}

int main(int argc, char* argv[]) {
    // Flush after every std::cout / std::cerr
    std::cout << std::unitbuf;
    std::cerr << std::unitbuf;

    // Disable output buffering
    setbuf(stdout, NULL);

    // Check if resolver address is provided
    if (argc < 3 || std::string(argv[1]) != "--resolver") {
        std::cerr << "Usage: " << argv[0] << " --resolver <ip:port>" << std::endl;
        return 1;
    }
    
    // Parse the resolver address
    ResolverAddress resolver = parseResolverAddress(argv[2]);
    std::cout << "DNS Forwarder starting up, using resolver " << resolver.ip << ":" << resolver.port << std::endl;

    int udpSocket;
    struct sockaddr_in clientAddress;

    udpSocket = socket(AF_INET, SOCK_DGRAM, 0);
    if (udpSocket == -1) {
        std::cerr << "Socket creation failed: " << strerror(errno) << "..." << std::endl;
        return 1;
    }

    // Since the tester restarts your program quite often, setting REUSE_PORT
    // ensures that we don't run into 'Address already in use' errors
    int reuse = 1;
    if (setsockopt(udpSocket, SOL_SOCKET, SO_REUSEPORT, &reuse, sizeof(reuse)) < 0) {
        std::cerr << "SO_REUSEPORT failed: " << strerror(errno) << std::endl;
        return 1;
    }

    sockaddr_in serv_addr = { .sin_family = AF_INET,
                              .sin_port = htons(2053),
                              .sin_addr = { htonl(INADDR_ANY) },
                            };

    if (bind(udpSocket, reinterpret_cast<struct sockaddr*>(&serv_addr), sizeof(serv_addr)) != 0) {
        std::cerr << "Bind failed: " << strerror(errno) << std::endl;
        return 1;
    }

    unsigned char buffer[512];
    socklen_t clientAddrLen = sizeof(clientAddress);

    while (true) {
        // Receive data from client
        int bytesRead = recvfrom(udpSocket, buffer, sizeof(buffer), 0, 
                               reinterpret_cast<struct sockaddr*>(&clientAddress), &clientAddrLen);
        
        if (bytesRead == -1) {
            perror("Error receiving data");
            break;
        }

        std::cout << "Received " << bytesRead << " bytes from " 
                  << inet_ntoa(clientAddress.sin_addr) << ":" << ntohs(clientAddress.sin_port) << std::endl;

        // Parse the DNS header from the request
        DnsHeader requestHeader = parseDnsHeader(buffer);
        
        // Print parsed header for debugging
        printDnsHeader(requestHeader);
        
        // Check if there are questions in the packet
        if (requestHeader.qdcount > 0) {
            // Parse all questions
            std::vector<DnsQuestion> questions;
            int offset = 12; // Start of the first question (after the header)
            
            for (int i = 0; i < requestHeader.qdcount; i++) {
                int nextOffset;
                DnsQuestion question = parseDnsQuestion(buffer, offset, nextOffset, buffer);
                
                // Print parsed question for debugging
                std::cout << "Question " << (i + 1) << ":" << std::endl;
                printDnsQuestion(question);
                
                questions.push_back(question);
                offset = nextOffset;
            }
            
            // Forward each question to the resolver
            std::vector<std::vector<unsigned char>> responses;
            
            for (int i = 0; i < questions.size(); i++) {
                // Create a new query for each question
                std::vector<unsigned char> query = createDnsQuery(requestHeader.id, requestHeader, questions[i]);
                
                // Forward the query and get the response
                std::vector<unsigned char> response = forwardDnsQuery(query, resolver);
                
                if (!response.empty()) {
                    responses.push_back(response);
                }
            }
            
            // Create a merged response
            std::vector<unsigned char> mergedResponse = mergeDnsResponses(requestHeader.id, requestHeader, questions, responses);
            
            // Send the merged response back to the client
            if (sendto(udpSocket, mergedResponse.data(), mergedResponse.size(), 0, 
                      reinterpret_cast<struct sockaddr*>(&clientAddress), sizeof(clientAddress)) == -1) {
                perror("Failed to send response");
            } else {
                std::cout << "Sent DNS response with " << mergedResponse.size() << " bytes" << std::endl;
            }
        } else {
            std::cerr << "No questions in the request, not responding" << std::endl;
        }
    }

    close(udpSocket);
    
    return 0;
}