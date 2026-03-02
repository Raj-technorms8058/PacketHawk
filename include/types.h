//==================================================
//Core data structures for the PacketHawk DPI Engine
//==================================================
#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <optional> //for values that might or might not exist(like SNI)

//section:1 Application Types to which our traffic belongs
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

//section:2 FIVE TUPLE : unique fingerprint of every network connection
struct FiveTuple {
    unint32_t src_ip;
    unint32_t dst_ip;
    unint16_t src_port;
    unint16_t dst_port;
    uint8_t protocol; 
    //comparing 2 tuples
    bool operator==(const FiveTuple& other) const {
        return (src_ip   == other.src_ip)   &&
               (dst_ip   == other.dst_ip)   &&
               (src_port == other.src_port) &&
               (dst_port == other.dst_port) &&
               (protocol == other.protocol);
    }
    // This lets FiveTuple be used as a key in unordered_map
                    
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
};

//section:3 FLOW: represents complete comnection btw 2 devices
                //all packets with same 5-tuple belong to same flow

struct Flow {
    FiveTuple tuple;          //unique ID of this connection
    AppType app_type;       
    std::string sni;            
    bool blocked;        
    uint64_t packet_count;      uint64_t byte_count;     
    bool sni_extracted;  //we already extracted the SNI?

    //Constructor-default values when a Flow is created
    Flow() : app_type(AppType::UNKNOWN),
             blocked(false),
             packet_count(0),
             byte_count(0),
             sni_extracted(false) {}
};

//section:4 Raw Packet

struct RawPacket {
    std::vector<uint8_t> data;  //actual bytes of packet
    uint32_t ts_sec;       
    uint32_t ts_usec;           
    uint32_t orig_len;          // Original length before capture
};

// SECTION 5: Parsed Packet :packet AFTER we understand it

struct ParsedPacket {
    //Ethernet Layer
    std::string src_mac;       
    std::string dst_mac;       
    //IP Layer
    std::string src_ip;         
    std::string dst_ip;         
    uint8_t     ttl;            // Time To Live
    uint8_t     protocol;       // 6=TCP, 17=UDP

    //Transport Layer
    uint16_t    src_port;       
    uint16_t    dst_port;      
    bool        has_tcp;       
    bool        has_udp;       
    //if tcp then : TCP Flags
    uint32_t    seq_num;     
    uint32_t    ack_num;     
    bool        flag_syn;     
    bool        flag_ack;     
    bool        flag_fin;     
    bool        flag_rst;     
    bool        flag_psh;       // PSH-push data immediately

    //Payload
    std::vector<uint8_t> payload;   // actual data in packet
    size_t payload_length;          //total bytes of payload

    ParsedPacket() : ttl(0), protocol(0),
                     src_port(0), dst_port(0),
                     has_tcp(false), has_udp(false),
                     seq_num(0), ack_num(0),
                     flag_syn(false), flag_ack(false),
                     flag_fin(false), flag_rst(false),
                     flag_psh(false),
                     payload_length(0) {}
};

// SECTION 6: Block Rule: A single blocking rule loaded from our JSON config file
// Example:
//   Block IP:     { "type": "ip",     "value": "192.168.1.100" }
//   Block domain: { "type": "domain", "value": "youtube.com"   }
//   Block app:    { "type": "app",    "value": "YOUTUBE"       }

struct BlockRule {
    std::string type;    
    std::string value;  
};
//BlockRule rule1;
//rule1.type  = "ip";
//rule1.value = "192.168.1.105";
// Block ALL traffic from this specific device

// SECTION 7: Report Entry: final traffic report
// Example:
//   YouTube   | 150 packets | 2.3 MB | BLOCKED

struct ReportEntry {
    AppType     app_type;       // Which application
    std::string app_name;       // Human readable name e.g. "YouTube"
    uint64_t    packet_count;   
    uint64_t    byte_count;    
    double      percentage;     // Percentage of total traffic
    bool        was_blocked;    
};

