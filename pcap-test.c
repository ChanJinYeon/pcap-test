#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include "libnet-header.h"

void usage()
{
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test wlan0\n");
}

typedef struct
{
    char *dev_;
} Param;

Param param = {
    .dev_ = NULL};

bool parse(Param *param, int argc, char *argv[])
{
    if (argc != 2)
    {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

int main(int argc, char *argv[])
{
    if (!parse(&param, argc, argv))
        return -1;

    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
    if (pcap == NULL)
    {
        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        return -1;
    }

    while (true)
    {
        struct pcap_pkthdr *header;
        const u_char *packet;
        int res = pcap_next_ex(pcap, &header, &packet);
        if (res == 0)
            continue;
        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK)
        {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
            break;
        }

        struct libnet_ethernet_hdr *ethernet = (struct libnet_ethernet_hdr *)packet;
        struct libnet_ipv4_hdr *ip = NULL;
        struct libnet_tcp_hdr *tcp = NULL;

        // IP 헤더
        if (ntohs(ethernet->ether_type) == 0x0800)
        {
            ip = (struct libnet_ipv4_hdr *)(packet + sizeof(struct libnet_ethernet_hdr));
            // TCP 헤더
            if (ip->ip_p == 6)
            {
                // TCP 패킷만 정보 출력
                printf("%u bytes captured\n", header->caplen);

                tcp = (struct libnet_tcp_hdr *)(packet + sizeof(struct libnet_ethernet_hdr) + ip->ip_hl * 4);

                // Ethernet 정보 출력
                printf("src_MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       ethernet->ether_shost[0], ethernet->ether_shost[1], ethernet->ether_shost[2],
                       ethernet->ether_shost[3], ethernet->ether_shost[4], ethernet->ether_shost[5]);
                printf("dst_MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                       ethernet->ether_dhost[0], ethernet->ether_dhost[1], ethernet->ether_dhost[2],
                       ethernet->ether_dhost[3], ethernet->ether_dhost[4], ethernet->ether_dhost[5]);

                // IP 정보 출력
                printf("src_IP: %s\n", inet_ntoa(ip->ip_src));
                printf("dst_IP: %s\n", inet_ntoa(ip->ip_dst));

                // TCP 정보 출력
                printf("src_PORT: %d\n", ntohs(tcp->th_sport));
                printf("dst_PORT: %d\n", ntohs(tcp->th_dport));

                // data
                const u_char *payload = (const u_char *)tcp + (tcp->th_off * 4);
                int payload_len = ntohs(ip->ip_len) - (ip->ip_hl * 4) - (tcp->th_off * 4);
                printf("<payload>\n");
                if (payload_len > 0)
                {
                    for (int i = 0; i < payload_len && i < 20; i++)
                    {
                        printf("%02x ", payload[i]);
                    }
                    printf("\n");
                }
            }
        }
    }
    pcap_close(pcap);
}