#include "Packet.h"

bool Packet::openLiveCapture(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return false;
    }
    return true;
}


bool Packet::setMyInterfaceMac(){
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf("Fail to get interface MAC address - socket() failed - %m\n");
        return false;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return false;
    }
    memcpy(interfaceMac, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);
    close(sockfd);

    return true;
}


bool Packet::setMyInterfaceIp(){
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        printf("Fail to get interface IP address - socket() failed - %m\n");
        return false;
    }

    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    ret = ioctl(sockfd, SIOCGIFADDR, &ifr);
    if (ret < 0) {
        printf("Fail to get interface IP address - ioctl(SIOCGIFADDR) failed - %m\n");
        close(sockfd);
        return false;
    }

    interfaceIp = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;
    close(sockfd);

    return true;
}


bool Packet::setMyInterfaceInfo(){
    if (!setMyInterfaceMac()) return false;
    if (!setMyInterfaceIp()) return false;
    return true;
}


//Set Ethernet Header: srcMAC, dstMAC, Ethernet Type
void Packet::setEthHeader(u_int8_t* srcMac, u_int8_t* dstMac, u_int16_t ethType){
    for (int i = 0; i < ETH_ADDR_LEN; i++){
        ethArpPacket.eth.srcMac[i] = srcMac[i];
        ethArpPacket.eth.dstMac[i] = dstMac[i];
    }
    ethArpPacket.eth.ethType = htons(ethType);
}


//Set ARP Header: srcMAC, srcIP, dstMAC, dstIP, opCode
void Packet::setArpHeader(u_int8_t* srcMac, u_int32_t srcIp, u_int8_t* dstMac, u_int32_t dstIp, u_int16_t opCode){
    for (int i = 0; i < ETH_ADDR_LEN; i++){
        ethArpPacket.arp.srcMac[i] = srcMac[i];
        ethArpPacket.arp.dstMac[i] = dstMac[i];
    }
    ethArpPacket.arp.srcIp = srcIp;
    ethArpPacket.arp.dstIp = dstIp;
    ethArpPacket.arp.op = htons(opCode);
}

void Packet::sendPacket(){
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&ethArpPacket), sizeof(ethArpHdr));
    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}

packetInfo Packet::captureNextPacket(){
    packetInfo capturedPacketInfo;
    capturedPacketInfo.status = pcap_next_ex(pcap, &capturedPacketInfo.header, &capturedPacketInfo.packet);
    return capturedPacketInfo;
}


void Packet::resolveMacByIp(u_int32_t ip){
    while (true){
        packetInfo capturedPacketInfo = captureNextPacket();
        if (capturedPacketInfo.status == 0) continue;
        if (capturedPacketInfo.status == PCAP_ERROR || capturedPacketInfo.status == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", capturedPacketInfo.status , pcap_geterr(pcap));
            break;
        }

        ethArpHdr* capturedPacket = (ethArpHdr*)(capturedPacketInfo.packet);
        if (ntohs(capturedPacket->eth.ethType) == ethHdr::ARP && capturedPacket->arp.srcIp == ip){
            for (int i = 0; i < ETH_ADDR_LEN; i++)  arpTable[ip][i] = capturedPacket->eth.srcMac[i];   // Potential issue point – check here
            break;
        }
    }
}


void Packet::closeLiveCapture(){
    pcap_close(pcap);
    fprintf(stderr, "close\n");
}


