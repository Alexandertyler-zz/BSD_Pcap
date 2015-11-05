#include <pcap.h>
#include <ctype.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

void proc_packet(u_char *args, const struct pcap_pkthdr *pkt_header, const u_char *pkt);
