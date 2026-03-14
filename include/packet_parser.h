//=========================================
// PacketHawk - packet_parser.h
// parses raw packet bytes into understood data
//=========================================

#pragma once

#include "types.h"
#include <string>
#include <cstdint>

using namespace std;

class PacketParser {
public:

    // main entry point - takes raw packet fills parsed packet
    static bool parse(const RawPacket& raw, ParsedPacket& parsed);

private:

    // each layer has its own parser
    // uint8_t* is pointer to bytes, len tracks available bytes
    static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed);
    static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed);
    static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed);
    static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed);

    // raw bytes to readable strings
    static string macToString(const uint8_t* mac);
    static string ipToString(uint32_t ip);

};
```

