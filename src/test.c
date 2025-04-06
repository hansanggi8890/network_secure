#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <arpa/inet.h>

/* Ethernet header */
struct ethheader {
    unsigned char  ether_destination_host[6]; // Destination address(hex)
    unsigned char  ether_source_host[6]; // Source address(hex)
    unsigned short ether_type;     // Protocol type (ipv4, ipv6, arp, ---)
};

/* IP header */
struct ipheader {
    unsigned char      iph_ip_header_lenght:4, // ip header lenght 
		               iph_version:4; // ip version

    unsigned char      iph_type_of_service; // type of service
    unsigned short int iph_length; // ip packet length
    unsigned short int iph_identification; // identification
    unsigned short int iph_flag:3,  // fragmentation flags
		               iph_flag_offset:13; // flag offset

    unsigned char      iph_time_to_live; // time to live
    unsigned char      iph_protocol; // protocol type
    unsigned short int iph_chksum; // ip datagram checksum
    struct  in_addr    iph_source_ip; // souce ip address
    struct  in_addr    iph_destination_ip; // destination ip address
};

/* TCP header */
struct tcpheader {
    unsigned short tcp_source_port;  // Source port
    unsigned short tcp_destination_port;  // Destination port
			
    unsigned int   tcp_sequence;    // Sequence Number
    unsigned int   tcp_acknonwledge;    // Acknowledgement Number

    unsigned char  tcp_offset:4; // data offset
    unsigned char  tcp_reserved:4; // reserved

    unsigned char  tcp_flags; // control flags

    unsigned short tcp_window; // window size
    unsigned short tcp_checksum; // checksum
    unsigned short tcp_urgent; // urgent pointer
};

int count = 1;

void got_packet(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet) {
    const struct ethheader *eth = (struct ethheader *)packet;

    const struct ipheader *iph = (struct ipheader *)(packet + sizeof(struct ethheader));

    if(ntohs(eth->ether_type) != 0x0800) { // check ipv4
	    return;
    }

    int ip_header_length = iph->iph_ip_header_lenght * 4;
    const struct tcpheader *tcph = (struct tcpheader *)((unsigned char *)iph + ip_header_length);

    int tcp_header_length = tcph->tcp_offset * 4;
    const unsigned char *message = (unsigned char *)tcph + tcp_header_length;

    int total_headers_size = sizeof(struct ethheader) + ip_header_length + tcp_header_length;
    int message_size = header->caplen - total_headers_size;

    // ip
    char source_ip = inet_ntoa(iph->iph_source_ip);
    char destination_ip = inet_ntoa(iph->iph_destination_ip);

    // port
    int source_port = ntohs(tcph->tcp_source_port);
    int destination_port = ntohs(tcph->tcp_destination_port);


    printf("\n[TCP capture start point(count : %d)]\n",count);
    count++;

    // Ethernet Header
    printf("[Ethernet Header]\n");
    printf("Source MAC : ");
    for(int i=0; i<6; i++) {
        printf("%02x:",eth->ether_source_host[i]);
    }
    printf("\b\n");
    printf("Destination MAC : ");
    for(int i=0; i<6; i++) {
        printf("%02x:",eth->ether_destination_host[i]);
    }
    printf("\b\n");
    
    // IP Header
    printf("[IP Header]\n");
    printf("Source IP : %s\n", source_ip);
    printf("Destination IP : %s\n", destination_ip);

    // TCP Header
    printf("[TCP Header]\n");
    printf("Source Port : %d\n", source_port);
    printf("Destination Port : %d\n", destination_port);

    // Message (data)
    printf("[Message] length : %d\n", message_size); // message full length
    if (message_size > 0) {
        int print_len = message_size > 64 ? 64 : message_size; // message size check / cut 64byte
        printf("Hex Data : ");
        for (int i = 0; i < print_len; i++) {
            printf("%02x ", message[i]);
        }
        printf("\n");

        printf("Ascii Data : ");
        for (int i = 0; i < print_len; i++) { 
            if (message[i] >= 32 && message[i] <= 126) // check strings
                printf("%c", message[i]);
            else
                printf("."); // if not strings = "."
        }
        printf("\n");
    } else {
        printf("No Data\n");
    }
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct bpf_program fp;
    char filter_exp[] = "tcp and port 80"; // filter tcp and 80 port
    bpf_u_int32 net;

    handle = pcap_open_live("enp0s3", BUFSIZ, 1, 1000, errbuf); // network card capture setting

    pcap_compile(handle, &fp, filter_exp, 0, net); // set filter
    if (pcap_setfilter(handle, &fp)!=0) {
        pcap_perror(handle, "Error:");
        exit(EXIT_FAILURE);
    }

    printf("[Start sniffing]\n");

    pcap_loop(handle, -1, got_packet, NULL);

    pcap_close(handle);
    return 0;
}