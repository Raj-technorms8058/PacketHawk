//=======================================
//parses raw packet into understood data
//=======================================
#pragma once
#include "types.h"
#include <string>
#include <cstdint>

class PacketParser {
    public:
        //take raw packet, fills parsed packet
        static bool parse(const RawPacket& raw, ParsedPacket& parsed);
    private:
        //static means no object needed, just can call directly
        //uint8_t* is pointer to bytes of rawpacket's data that is filled after the reader
        //len keeps track of how many bytes are available from that point
        static bool parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed);//first 14 byte
        static bool parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed);//next 20 bytes
        static bool parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed);//next 20 bytes
        static bool parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed);//next 8 bytes

        //helper functions
        static std::string macToString(const uint8_t* mac);
        static std::string ipToString(uint32_t ip);
};
