//==========================================
// actual implementation of PcapReader class
//==========================================

#include "pcap_reader.h"
#include <iostream>

PcapReader::PcapReader()
    : is_open_(false), packet_count_(0) {
}
PcapReader::~PcapReader() {
    close();
}

// open pcap file and check if its valid
bool PcapReader::open(const std::string& filename) {

    // connect file_ to the pcap file in binary mode
    file_.open(filename, std::ios::binary);

    // did it open?
    if (!file_.is_open()) {
        std::cerr << "[PacketHawk] ERROR: Cannot open file: "
                  << filename << std::endl;
        return false;
    }

    // read first 24 bytes into global_header_
    file_.read(reinterpret_cast<char*>(&global_header_),
               sizeof(PcapGlobalHeader));

    // did we get 24 bytes
    if (file_.gcount() != sizeof(PcapGlobalHeader)) {
        std::cerr << "[PacketHawk] ERROR: File too small"
                  << std::endl;
        file_.close();
        return false;
    }

    // check secret stamp,real pcap?
    if (global_header_.magic_number != 0xa1b2c3d4 &&
        global_header_.magic_number != 0xd4c3b2a1) {
        std::cerr << "[PacketHawk] ERROR: Not a valid PCAP file"
                  << std::endl;
        file_.close();
        return false;
    }
    is_open_ = true;
    packet_count_ = 0;

    std::cout << "[PacketHawk] Opened: " << filename << std::endl;
    return true;
}

// read next packet from file
bool PcapReader::readNextPacket(RawPacket& packet) {

    // file not open? stop
    if (!is_open_) return false;

    // read 16 byte packet label
    PcapPacketHeader pkt_header;
    file_.read(reinterpret_cast<char*>(&pkt_header),
               sizeof(PcapPacketHeader));

    // couldnt read 16 bytes = end of file
    if (file_.gcount() != sizeof(PcapPacketHeader)) {
        return false;
    }

    // packet too big? skip
    if (pkt_header.incl_len > 65535) {
        return false;
    }

    // fill rawpacket with timestamp info
    packet.ts_sec   = pkt_header.ts_sec;
    packet.ts_usec  = pkt_header.ts_usec;
    packet.orig_len = pkt_header.orig_len;

    // make space for packet bytes
    packet.data.resize(pkt_header.incl_len);

    // read actual packet bytes
    file_.read(reinterpret_cast<char*>(packet.data.data()),
               pkt_header.incl_len);

    // got all bytes?
    if (file_.gcount() != static_cast<std::streamsize>(pkt_header.incl_len)) {
        return false;
    }

    // one more packet done
    packet_count_++;

    return true;
}

// close file
void PcapReader::close() {
    if (file_.is_open()) {
        file_.close();
    }
    is_open_ = false;
}

//file open?
bool PcapReader::isOpen() const {
    return is_open_;
}

//packets read till now
uint64_t PcapReader::getPacketCount() const {
    return packet_count_;
}