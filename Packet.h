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
    int status; //Return value of captureNextPacket()
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
    pcap_t* pcap; //Packet Caputre Handle
    char* dev; //Interface Dev (eth0, wlan0...)

    //Interface Info
    u_int8_t interfaceMac[ETH_ADDR_LEN];
    u_int32_t interfaceIp;
    bool setMyInterfaceMac();
    bool setMyInterfaceIp();

    //Headers
    ethHdr ethHeader;
    arpHdr arpHeader;
    ipv4Hdr Ipv4Header;
    ethArpHdr ethArpHeader;
    ethIpv4Hdr ethIpv4Header;

    //arpTables
    std::map<u_int32_t, u_int8_t[ETH_ADDR_LEN]> arpTable;
    std::vector<SenderTargetPair> senderTargetTable;  // Need to remove duplicates

public:
    //Setting
    void setDev(char* device){ dev = device; }
    bool setMyInterfaceInfo();

    //Open
    bool openLiveCapture();

    //SetHeader
    void setEthHeader(u_int8_t* srcMac, u_int8_t* dstMac, u_int16_t ethType);
    void setArpHeader(u_int8_t* srcMac, u_int32_t srcIp, u_int8_t* dstMac, u_int32_t dstIp, u_int16_t opCode);

    //SendPacket
    void sendPacket(); //Insert the configured header into the packet and send it (header configuration required!!)
    void sendPacket(const u_char* packet); //Send the entire packet as an argument

    //CapturePacket
    packetInfo captureNextPacket();

    //ResolveMac
    void resolveMacByIp(u_int32_t ip);
    void resolveMacByIpforSpoof(u_int32_t senderIp, u_int32_t targetIp);

    //Spoofing
    void sendSpoofedPacket(u_int32_t senderIp, u_int32_t targetIp, u_int16_t opCode);
    void continuousArpSpoofing();

    //Close
    void closeLiveCapture(){ pcap_close(pcap); }
};

