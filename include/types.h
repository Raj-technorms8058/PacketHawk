//==================================================
// PacketHawk - types.h
// core data structures for the PacketHawk DPI Engine
//==================================================

#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <optional>

enum class AppType {
    UNKNOWN,
    HTTP,
    HTTPS,
    DNS,
    YOUTUBE,
    FACEBOOK,
    GOOGLE,
    INSTAGRAM,
    TWITTER,
    NETFLIX,
    WHATSAPP,
    TORRENT
};

struct FiveTuple {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;

    bool operator==(const FiveTuple& other) const {
        return (src_ip   == other.src_ip)   &&
               (dst_ip   == other.dst_ip)   &&
               (src_port == other.src_port) &&
               (dst_port == other.dst_port) &&
               (protocol == other.protocol);
    }
};

struct FiveTupleHash {
    size_t operator()(const FiveTuple& t) const {
        size_t h = 0;
        h ^= std::hash<uint32_t>{}(t.src_ip)   + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint32_t>{}(t.dst_ip)   + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(t.src_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint16_t>{}(t.dst_port) + 0x9e3779b9 + (h << 6) + (h >> 2);
        h ^= std::hash<uint8_t> {}(t.protocol) + 0x9e3779b9 + (h << 6) + (h >> 2);
        return h;
    }
};

struct Flow {
    FiveTuple   tuple;
    AppType     app_type;
    std::string sni;
    bool        blocked;
    uint64_t    packet_count;
    uint64_t    byte_count;
    bool        sni_extracted;

    Flow() : app_type(AppType::UNKNOWN),
             blocked(false),
             packet_count(0),
             byte_count(0),
             sni_extracted(false) {}
};

struct RawPacket {
    std::vector<uint8_t> data;
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t orig_len;
};

struct ParsedPacket {
    std::string src_mac;
    std::string dst_mac;

    std::string src_ip;
    std::string dst_ip;
    uint8_t     ttl;
    uint8_t     protocol;

    uint16_t    src_port;
    uint16_t    dst_port;
    bool        has_tcp;
    bool        has_udp;

    uint32_t    seq_num;
    uint32_t    ack_num;
    bool        flag_syn;
    bool        flag_ack;
    bool        flag_fin;
    bool        flag_rst;
    bool        flag_psh;

    std::vector<uint8_t> payload;
    size_t               payload_length;

    ParsedPacket() : ttl(0), protocol(0),
                     src_port(0), dst_port(0),
                     has_tcp(false), has_udp(false),
                     seq_num(0), ack_num(0),
                     flag_syn(false), flag_ack(false),
                     flag_fin(false), flag_rst(false),
                     flag_psh(false),
                     payload_length(0) {}
};

struct BlockRule {
    std::string type;
    std::string value;
};

struct ReportEntry {
    AppType     app_type;
    std::string app_name;
    uint64_t    packet_count;
    uint64_t    byte_count;
    double      percentage;
    bool        was_blocked;
};
```

