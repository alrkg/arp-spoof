#pragma once
#include <pcap.h>

#define ETH_ADDR_LEN 6
#define IPV4_ADDR_LEN 4
#define ETH_HDR_LEN 14

extern u_int8_t BROADCAST_MAC[ETH_ADDR_LEN];
extern u_int8_t NULL_MAC[ETH_ADDR_LEN];


#pragma pack(push, 1)
//Ethernet Header
struct ethHdr
{
    u_int8_t dstMac[ETH_ADDR_LEN];
    u_int8_t srcMac[ETH_ADDR_LEN];
    u_int16_t ethType;

    enum eType
    {
        IPv4 = 0x0800,
        ARP = 0x0806,
        IPv6 = 0x06DD
    };
};

//ARP Header
struct arpHdr
{
    u_int16_t hrdType = htons(arpHdr::Ethernet);
    u_int16_t pType = htons(ethHdr::IPv4);
    u_int8_t hdrLen = ETH_ADDR_LEN;
    u_int8_t pLen = IPV4_ADDR_LEN;
    u_int16_t op;
    u_int8_t srcMac[ETH_ADDR_LEN];
    u_int32_t srcIp;
    u_int8_t dstMac[ETH_ADDR_LEN];
    u_int32_t dstIp;

    // Hardware Type
    enum: u_int16_t
    {
        Ethernet = 0x001,
        Wifi = 	0x001B,
        LTE = 0x001D,
        FiveG =	0x001E,
    };

    // Op Code
    enum: u_int16_t
    {
        ArpRequest = 0x0001,
        ArpReply = 0x0002,
        InArpRequest = 0x008,
        InArpReply = 0x009
    };
};

//IPv4 Header
struct ipv4Hdr
{
    u_int8_t versionAndIhl;
    u_int8_t dscpAndEcn;
    u_int16_t totalLen;
    u_int16_t identification;
    u_int16_t flagsAndOffset;
    u_int8_t ttl;
    u_int8_t protocol;
    u_int16_t checksum;
    u_int32_t srcIp;
    u_int32_t dstIp;
};

//Ethernet and ARP Heaeder for ARP Packet
struct ethArpHdr {
    struct ethHdr eth;
    struct arpHdr arp;
};

#pragma pack(pop)
