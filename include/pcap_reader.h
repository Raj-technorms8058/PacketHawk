//=========================================
// PacketHawk - pcap_reader.h
// reads packets from PCAP files one by one
//=========================================

#pragma once

#include <string>
#include <fstream>
#include <cstdint>
#include "types.h"

// 24 byte header at start of every pcap file
struct PcapGlobalHeader {
    uint32_t magic_number;   // must be 0xa1b2c3d4 else invalid
    uint16_t version_major;
    uint16_t version_minor;
    int32_t  thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};

// 16 byte label before every packet
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;   // bytes saved
    uint32_t orig_len;   // original size
};

// reads pcap and gives packets one by one to the engine
class PcapReader {
public:

    PcapReader();
    ~PcapReader();

    bool open(const std::string& filename);
    bool readNextPacket(RawPacket& packet);
    void close();
    bool isOpen() const;
    uint64_t getPacketCount() const;

private:

    std::ifstream    file_;
    bool             is_open_;
    uint64_t         packet_count_;
    PcapGlobalHeader global_header_;

};
```

