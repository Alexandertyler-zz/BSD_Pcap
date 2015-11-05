#include "bsd_pcap.h"

void
proc_packet(u_char *args, const struct pcap_pkthdr *pkt_header, const u_char pkt)
{
	struct ether_header *ether_h;
	struct ip *ip_h;
	struct udphdr *udp_h;
	const u_char *payload;
	u_int ip_s;

	//cast the packet into a series of headers that breaks it into chunks
	ether_h = (struct  ether_header *) pkt;

	ip_h = (struct ip *) (pkt + ETHER_HDR_LEN);
	ip_s = (ip_h->ip_hl) * 4;
	if (ip_s < 4)
	{
		fprintf(stderr, "Ip Header has invalid size: %u bytes\n", ip_s);
		return;
	}

	udp_h = (struct udphdr *) (pkt + ETHER_HDR_LEN + ip_s);

	payload = (const u_char *) (pkt + ETHER_HDR_LEN + ip_s + sizeof(udp_h));
	
	return;
}

	
int
main(int argc, char *argv[])
{
	char *dev, errbuf[PCAP_ERRBUF_SIZE];
	pcap_t *dev_handle;
	bpf_u_int32 mask, net;
	struct bpf_program fp;
	char filter[] = "udp";

	// This block attempts to grab the default network interface
	if ((dev = pcap_lookupdev(errbuf)) == NULL)
	{
		fprintf(stderr, "Unable to locate the default device: %s\n", errbuff);
		return(1);
	}
	fprintf(stdout, "Using device: %s\n", dev);

	//This block attempts to find the ip and netmask for the device
	if (pcap_lookupdev(dev, &net &mask, errbuf) == -1)
	{
		fprintf(stderr, "Unable to locate the device netmask: %s\n", errbuf);
		net = 0;
		mask = 0;
	}

	//This block opens the device handle so we can read from it
	if ((dev_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf)) == NULL)
	{
		fprintf(stderr, "Unable to open device %s for reading: %s\n", dev, errbuf);
		return(1);
	}

	//Check if the device supports ethernet headers, otherwise we can't handle parsing it
	if (pcap_datalink(dev_handle) != DLT_EN10MB)
	{
		fprintf(stderr, "No ethernet header support for device %s\n", dev);
		return(1);
	}

	//Compile a filter that pcap uses, drop all traffic that doesn't match
	if (pcap_compile(dev_handle, &fp, filter, 0, net) == -1)
	{
		fprintf(stderr, "Unable to parse the pcap filter '%s': %s\n", filter, pcap_geterr(dev_handle));
		return(1);
	}

	if (pcap_setfilter(dev_handle, &fp) == -1)
	{
		fprintf(stderr, "Unable to apply the pcap filter '%s': %s\n", filter, pcap_geterr(dev_handle));
		return(1);
	}

	//Device should be fully configured, enter a listening loop to monitor traffic
	if (pcap_loop(dev_handle, -1, proc_packet, NULL) == -1)
	{
		fprintf(stderr, "Loop handler failed %s\n", dev);
		return(1);
	}

	return(0);
