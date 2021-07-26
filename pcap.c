#include <pcap.h>
#include <stdio.h>
#include <libnet.h>
#include <stdint.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test eth0\n");
}

int main(int argc, char *argv[]) {
	if (argc != 2){
		usage();
		return 1;
	}
    char   *dev = argv[1];
    char    errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {
		fprintf(stderr, " Couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}
    int i = 0;
    while(1) {
        i++;
        struct pcap_pkthdr *header;
        const uint8_t      *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("--------- Packet Number %d ---------\n",i);
        printf("---Packet len : %u\n",header->caplen);
        
        struct libnet_ethernet_hdr *eth = (struct libnet_ethernet_hdr *)packet;
        printf("---MAC SRC: ");
        for (int i = 0; i< ETHER_ADDR_LEN-1; ++i)
            printf("%02x:", eth->ether_shost[i]);
        printf("%02x", eth->ether_shost[ETHER_ADDR_LEN-1]);
        
        printf("\n---MAC DST: ");
        for (int i = 0; i< ETHER_ADDR_LEN-1; ++i)
            printf("%02x:", eth->ether_dhost[i]);
        printf("%02x", eth->ether_dhost[ETHER_ADDR_LEN-1]);
        
        int eth_type = ntohs(eth->ether_type);
        if(eth_type!=ETHERTYPE_IP) continue;

        const struct libnet_ipv4_hdr *ipv4 = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
        printf("\n---IP SRC : %s\n", inet_ntoa(ipv4->ip_src));
        printf("---IP DST : %s\n", inet_ntoa(ipv4->ip_dst));

        uint16_t protocol = ipv4->ip_p;
        if (protocol != IPPROTO_TCP) continue;

        const struct libnet_tcp_hdr *tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + (ipv4->ip_hl << 2));
        printf("---PORT SRC : %d\n", ntohs(tcp->th_sport));
        printf("---PORT DST : %d\n", ntohs(tcp->th_dport));

        uint32_t data_len = ntohs(ipv4->ip_len) - (ipv4->ip_hl << 4) - (tcp->th_off << 4);
        uint8_t end = sizeof(struct libnet_ethernet_hdr) + (ipv4->ip_hl << 2) + (tcp->th_off << 2);
        uint8_t start = (end >> 4) << 4;

        printf("---TCP len: %u\n",data_len);
        printf("---Payload : ");
        for (int i = start; (i < end + 8) && (i < end + data_len); ++i)
            if(i < end)printf("XX");
        	else printf("%02x ", packet[i]); 
        printf("\n");
    }
     pcap_close(pcap);
}
