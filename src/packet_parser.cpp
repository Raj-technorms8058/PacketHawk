//=========================================
// PacketHawk - packet_parser.cpp
// parses raw packet bytes into understood data
//=========================================

#include "packet_parser.h"
#include <sstream>
#include <iomanip>

using namespace std;

bool PacketParser::parse(const RawPacket& raw, ParsedPacket& parsed) {
    if (raw.data.size() < 14)
        return false;
    const uint8_t* data = raw.data.data();
    size_t len = raw.data.size();
    return parseEthernet(data, len, parsed);
}

bool PacketParser::parseEthernet(const uint8_t* data, size_t len, ParsedPacket& parsed) {
    if (len < 14)
        return false;
    parsed.dst_mac = macToString(data);
    parsed.src_mac = macToString(data + 6);
    uint16_t ethertype = (data[12] << 8) | data[13];
    if (ethertype == 0x0800)
        return parseIPv4(data + 14, len - 14, parsed);
    return true;
}

bool PacketParser::parseIPv4(const uint8_t* data, size_t len, ParsedPacket& parsed) {
    if (len < 20)
        return false;
    uint8_t ihl = (data[0] & 0x0F) * 4;
    parsed.ttl      = data[8];
    parsed.protocol = data[9];
    uint32_t src_ip =
        (static_cast<uint32_t>(data[12]) << 24) |
        (static_cast<uint32_t>(data[13]) << 16) |
        (static_cast<uint32_t>(data[14]) << 8)  |
        static_cast<uint32_t>(data[15]);
    parsed.src_ip = ipToString(src_ip);
    uint32_t dst_ip =
        (static_cast<uint32_t>(data[16]) << 24) |
        (static_cast<uint32_t>(data[17]) << 16) |
        (static_cast<uint32_t>(data[18]) << 8)  |
        static_cast<uint32_t>(data[19]);
    parsed.dst_ip = ipToString(dst_ip);
    if (parsed.protocol == 6) {
        parsed.has_tcp = true;
        return parseTCP(data + ihl, len - ihl, parsed);
    }
    else if (parsed.protocol == 17) {
        parsed.has_udp = true;
        return parseUDP(data + ihl, len - ihl, parsed);
    }
    return true;
}

bool PacketParser::parseTCP(const uint8_t* data, size_t len, ParsedPacket& parsed) {
    if (len < 20)
        return false;
    parsed.src_port = (data[0] << 8) | data[1];
    parsed.dst_port = (data[2] << 8) | data[3];
    parsed.seq_num =
        (static_cast<uint32_t>(data[4]) << 24) |
        (static_cast<uint32_t>(data[5]) << 16) |
        (static_cast<uint32_t>(data[6]) << 8)  |
        static_cast<uint32_t>(data[7]);
    parsed.ack_num =
        (static_cast<uint32_t>(data[8])  << 24) |
        (static_cast<uint32_t>(data[9])  << 16) |
        (static_cast<uint32_t>(data[10]) << 8)  |
        static_cast<uint32_t>(data[11]);
    uint8_t tcp_header_len = ((data[12] >> 4) & 0x0F) * 4;
    parsed.flag_fin = (data[13] & 0x01) != 0;
    parsed.flag_syn = (data[13] & 0x02) != 0;
    parsed.flag_rst = (data[13] & 0x04) != 0;
    parsed.flag_psh = (data[13] & 0x08) != 0;
    parsed.flag_ack = (data[13] & 0x10) != 0;
    if (len > tcp_header_len) {
        parsed.payload.assign(data + tcp_header_len, data + len);
        parsed.payload_length = parsed.payload.size();
    }
    return true;
}

bool PacketParser::parseUDP(const uint8_t* data, size_t len, ParsedPacket& parsed) {
    if (len < 8)
        return false;
    parsed.src_port = (data[0] << 8) | data[1];
    parsed.dst_port = (data[2] << 8) | data[3];
    if (len > 8) {
        parsed.payload.assign(data + 8, data + len);
        parsed.payload_length = parsed.payload.size();
    }
    return true;
}

string PacketParser::macToString(const uint8_t* mac) {
    ostringstream oss;
    for (int i = 0; i < 6; i++) {
        if (i > 0)
            oss << ":";
        oss << hex
            << uppercase
            << setw(2)
            << setfill('0')
            << (int)mac[i];
    }
    return oss.str();
}

string PacketParser::ipToString(uint32_t ip) {
    ostringstream oss;
    oss << ((ip >> 24) & 0xFF) << "."
        << ((ip >> 16) & 0xFF) << "."
        << ((ip >> 8)  & 0xFF) << "."
        << (ip & 0xFF);
    return oss.str();
}
