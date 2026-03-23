#pragma once

#include "types.h"
#include <string>
#include <cstdint>

class PacketParser {
public:
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

private:
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed);

    static std::string macToString(const uint8_t* mac);
    static std::string ipToString(uint32_t ip);
};