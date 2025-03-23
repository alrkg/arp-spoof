#include "Packet.h"
#include "ArgParser.h"
#include "Headers.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
    Packet packet;

    u_int32_t senderIp = inet_addr(argv[2]);
    u_int32_t targetIp = inet_addr(argv[3]);

    //Check argument count and validate the format of the IP address
    if (!parse(argc, argv)) return EXIT_FAILURE;

    //Set network interface (dev)
    packet.setDev(argv[1]);

    //Open the specified dev interface and initialize the packet capture session
    if(!packet.openLiveCapture()) return EXIT_FAILURE;

    //Set the interface information (IP and MAC) for the packet capture;
    if(!packet.setMyInterfaceInfo()) return EXIT_FAILURE;

    //Set Ethernet header and ARP header
    packet.setEthHeader(packet.getInterfaceMac(), BROADCAST_MAC, ethHdr::ARP);
    packet.setArpHeader(packet.getInterfaceMac(), packet.getInterfaceIp(), NULL_MAC, senderIp, arpHdr::ArpRequest);

    //Send the packet
    packet.sendPacket();

    // Get MAC address from IP address
    packet.resolveMacByIp(senderIp);

    //Close the live capture session
    packet.closeLiveCapture();
}
