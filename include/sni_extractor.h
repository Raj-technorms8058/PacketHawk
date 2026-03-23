//=========================================
// PacketHawk - sni_extractor.h
// extracts domain name from TLS Client Hello
//=========================================

#pragma once

#include "types.h"
#include <string>
#include <optional>
using namespace std;
class SNIExtractor {
public:
    // returns domain name if found, nullopt if not
    static optional<string> extract(const uint8_t* data, size_t length);
private:
    // checks if this is actually a TLS Client Hello
    static bool isClientHello(const uint8_t* data, size_t length);
    // searches through extensions to find SNI
    static optional<string> findSNI(const uint8_t* data, size_t length, size_t offset);
};