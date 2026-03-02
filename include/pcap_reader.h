//=========================================
//Reads packets from PCAP files one by one
//=========================================

#pragma once

#include <string>
#include <fstream>
#include <cstdint>
#include "types.h"

//PCAP file start with this 24 byte header
//magic number tell us if it actually is a pcap file
struct PcapGlobalHeader {
    uint32_t magic_number;   //must be 0xa1b2c3d4 else invalid
    uint16_t version_major;  
    uint16_t version_minor;  
    int32_t  thiszone;       //timezone, mostly 0
    uint32_t sigfigs;        //timestamp accuracy, mostly 0
    uint32_t snaplen;        //max packet size captured
    uint32_t network;        //link type,1 means ethernet
};

//every packet in pcap has this 16 byte label before its data
struct PcapPacketHeader {
    uint32_t ts_sec;        
    uint32_t ts_usec;        
    uint32_t incl_len;       //total bytes saved
    uint32_t orig_len;       //original size on network
};

//read pcap file and give packet one by one to the engine
class PcapReader {
public:
    PcapReader();   //initializes PcapReader to safe default state

    ~PcapReader();  //this is destructor

    //open the pcap file,checks validity,false if invalid
    bool open(const std::string& filename);

    //read next packet,false when no more packet
    bool readNextPacket(RawPacket& packet);

    void close();              //close file
    bool isOpen() const;       //check if file is open
    uint64_t getPacketCount() const;  //total packets read

private:
    std::ifstream    file_;          //pcap file
    bool             is_open_;       //file open or not
    uint64_t         packet_count_;  //packet counter
    PcapGlobalHeader global_header_; //global header storage
};