#include "ArgParser.h"

bool parse(int argc, char* argv[]){
    if (argc < 4 && argc % 2 != 0) {
        printf("syntax : send-arp <interface> <sender ip> <target ip>\n");
        printf("sample : send-arp wlan0 192.168.10.2 192.168.10.1\n");
        return false;
    }

    for (int i = 2; i < argc; i++){
        if (inet_addr(argv[i]) == INADDR_NONE){
            fprintf(stderr, "Error: Invalid IP address. Please ensure the format is correct.\n");
            return false;
        }
    }
    return true;
}


