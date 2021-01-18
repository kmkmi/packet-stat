#pragma once

#include <cstdint>
#include <cstring>
#include <string>

typedef struct EP_Value {
    unsigned int Tx_Packets;
    unsigned int Tx_Bytes;
    unsigned int Rx_Packets;
    unsigned int Rx_Bytes;

} EP_Value;

typedef struct Flow_Value {
    unsigned int Packets;
    unsigned int Bytes;

} Flow_Value;


typedef struct Mac final {
    static const int SIZE = 6;
    uint8_t mac_[SIZE];

    //
    // constructor
    //
    Mac() {}
    Mac(const uint8_t* r) { memcpy(this->mac_, r, SIZE); }
    Mac(const std::string r);


    // casting operator
    //
    operator uint8_t*() const { return const_cast<uint8_t*>(mac_); } // default
    explicit operator std::string() const;

    //
    // comparison operator
    //

    bool operator < (const Mac& r) const
    {
       for (int i=0; i<6; i++){
           if(mac_[i] == r.mac_[i])
               continue;
           return mac_[i] > r.mac_[i];
       }
       return false;
    };

    bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; };



} Mac;

Mac::Mac(const std::string r) {
    unsigned int a, b, c, d, e, f;
    int res = sscanf(r.c_str(), "%02X:%02X:%02X:%02X:%02X:%02X", &a, &b, &c, &d, &e, &f);
    if (res != SIZE) {
        fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
        return;
    }
    mac_[0] = a;
    mac_[1] = b;
    mac_[2] = c;
    mac_[3] = d;
    mac_[4] = e;
    mac_[5] = f;
}

Mac::operator std::string() const {
    char buf[32]; // enough size
    sprintf(buf, "%02x:%02X:%02X:%02X:%02X:%02X",
        mac_[0],
        mac_[1],
        mac_[2],
        mac_[3],
        mac_[4],
        mac_[5]);
    return std::string(buf);
}

