#include "Packet.h"
#include "ArgParser.h"
#include "Headers.h"
#include <stdlib.h>

int main(int argc, char* argv[])
{
    Packet packet;

    if (!parse(argc, argv)) return EXIT_FAILURE; //Validate IP format
    packet.setDev(argv[1]); //Set network interface
    if(!packet.setMyInterfaceInfo()) return EXIT_FAILURE; //Set interface info (IP & MAC)
    if(!packet.openLiveCapture()) return EXIT_FAILURE; //Open interface and init capture

    //Resolve MAC, store, and spoof ARP
    for (int i = 2; i < argc; i += 2){
        u_int32_t senderIp = inet_addr(argv[i]);
        u_int32_t targetIp = inet_addr(argv[i+1]);
        packet.resolveMacByIpforSpoof(senderIp, targetIp);
        packet.sendSpoofedPacket(senderIp, targetIp, arpHdr::ArpRequest);
    }

    packet.continuousArpSpoofing(); //Maintain ARP spoofing & relay packets
    packet.closeLiveCapture(); //Close capture session
}
