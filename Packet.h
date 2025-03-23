#pragma once
#include <pcap.h>
#include <stdio.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
#include "Headers.h"
#include <map>
#include <array>
#include <vector>

#pragma pack(push, 1)
struct packetInfo
{
    struct pcap_pkthdr* header;
    const u_char* packet;
    int status; //
};

struct IpMacPair
{
    u_int32_t ip;
    u_int8_t mac[ETH_ADDR_LEN];
};

struct SenderTargetPair
{
    IpMacPair sender;
    IpMacPair target;
};
#pragma pack(pop)

class Packet
{

private:
    char* dev;  // Interface Dev (eth0, wlan0...)
    pcap_t* pcap;
    u_int8_t interfaceMac[ETH_ADDR_LEN];
    u_int32_t interfaceIp;
    ethArpHdr ethArpPacket;    // -> cancel
    u_int8_t senderMac[ETH_ADDR_LEN];
    std::map<u_int32_t, u_int8_t[ETH_ADDR_LEN]> arpTable;
    std::vector<SenderTargetPair> senderTargetTable;  // Need to remove duplicates
    bool setMyInterfaceMac();
    bool setMyInterfaceIp();

public:
    void setDev(char* device){ dev = device; }
    u_int8_t* getInterfaceMac(){ return interfaceMac; }
    u_int32_t getInterfaceIp(){ return interfaceIp; }
    bool openLiveCapture();
    bool setMyInterfaceInfo();
    void setEthHeader(u_int8_t* srcMac, u_int8_t* dstMac, u_int16_t ethType);
    void setArpHeader(u_int8_t* srcMac, u_int32_t srcIp, u_int8_t* dstMac, u_int32_t dstIp, u_int16_t opCode);
    void sendPacket();
    packetInfo captureNextPacket();
    void resolveMacByIp(u_int32_t ip);
    void resolveMacByIpforSpoof(u_int32_t senderIp, u_int32_t targetIp);
    void sendSpoofedPacket(u_int32_t senderIp, u_int32_t targetIp, u_int16_t opCode);
    void continuousArpSpoofing();
    void closeLiveCapture();
};

