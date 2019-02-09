#define RETSIGTYPE void
#include <sys/types.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#ifndef setsignal_h
#define setsignal_h

RETSIGTYPE (*setsignal(int, RETSIGTYPE (*)(int)))(int);
#endif

void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p);

int packettype;

char *program_name;

/* Externs */
extern void bpf_dump(const struct bpf_program *, int);

extern char *copy_argv(char **);

/* Forwards */
 void program_ending(int);

/* Length of saved portion of packet. */
int snaplen = 1500;;

static pcap_t *pd;

extern int optind;
extern int opterr;
extern char *optarg;
int pflag = 0, aflag = 0;


/* variables to store number of packets */
u_int num_broadcast_packets = 0;
u_int num_ip_packets = 0;
u_int num_arp_packets = 0;
u_int num_icmp_packets = 0;
u_int num_tcp_packets = 0;
u_int num_udp_packets = 0;
u_int num_dns_packets = 0;
u_int num_smtp_packets = 0;
u_int num_pop_packets = 0;
u_int num_imap_packets = 0;
u_int num_http_packets = 0;

/* struct for packets */

typedef struct arp_header_struct {
	uint16_t h_type; 
	uint16_t p_type;
	uint8_t h_size;
	uint8_t p_size;
	uint16_t opcode;
	uint8_t snd_mac_addr[6];
	uint8_t snd_ip_addr[4];
	uint8_t tgt_mac_addr[6];
	uint8_t tgt_ip_addr[4];
} arp_header_t;

typedef struct ip_header_struct {
	uint8_t header_len:4, version:4;
	uint8_t svc_field;
	uint16_t total_len;
	uint16_t id;
	uint16_t flags;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t checksum;
	uint8_t src[4];
	uint8_t dst[4];
} ip_header_t;

typedef struct icmp_header_struct {
	uint8_t type;
	uint8_t code; 
	uint16_t checksum;
	uint16_t id;
	uint16_t sequence;
} icmp_header_t;

typedef struct tcp_header_struct {
	uint16_t src_port;
	uint16_t dst_port; 
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t ns:1, reserved:3, data_offset:4;
	uint8_t fin:1, syn:1, rst:1, psh:1, ack:1, urg:1, ece:1, cwr:1;
	uint16_t win_size;
	uint16_t checksum;
	uint16_t urgent_p;
} tcp_header_t;

typedef struct udp_header_struct {
	uint16_t src_port;
	uint16_t dst_port; 
	uint16_t len;
	uint16_t checksum;
} udp_header_t;


int main(int argc, char **argv)
{
	int cnt, op, i, done = 0;
	bpf_u_int32 localnet, netmask;
	char *cp, *cmdbuf, *device;
	struct bpf_program fcode;
	 void (*oldhandler)(int);
	u_char *pcap_userdata;
	char ebuf[PCAP_ERRBUF_SIZE];

	cnt = -1;
	device = NULL;
	
	if ((cp = strrchr(argv[0], '/')) != NULL)
		program_name = cp + 1;
	else
		program_name = argv[0];

	opterr = 0;
	while ((i = getopt(argc, argv, "pa")) != -1)
	{
		switch (i)
		{
		case 'p':
			pflag = 1;
		break;
		case 'a':
			aflag = 1;
		break;
		case '?':
		default:
			done = 1;
		break;
		}
		if (done) break;
	}
	if (argc > (optind)) cmdbuf = copy_argv(&argv[optind]);
		else cmdbuf = "";

	if (device == NULL) {
		device = pcap_lookupdev(ebuf);
		if (device == NULL)
			error("%s", ebuf);
	}
	pd = pcap_open_live(device, snaplen,  1, 1000, ebuf);
	if (pd == NULL)
		error("%s", ebuf);
	i = pcap_snapshot(pd);
	if (snaplen < i) {
		warning("snaplen raised from %d to %d", snaplen, i);
		snaplen = i;
	}
	if (pcap_lookupnet(device, &localnet, &netmask, ebuf) < 0) {
		localnet = 0;
		netmask = 0;
		warning("%s", ebuf);
	}
	/*
	 * Let user own process after socket has been opened.
	 */
	setuid(getuid());

	if (pcap_compile(pd, &fcode, cmdbuf, 1, netmask) < 0)
		error("%s", pcap_geterr(pd));
	
	(void)setsignal(SIGTERM, program_ending);
	(void)setsignal(SIGINT, program_ending);
	/* Cooperate with nohup(1) */
	if ((oldhandler = setsignal(SIGHUP, program_ending)) != SIG_DFL)
		(void)setsignal(SIGHUP, oldhandler);

	if (pcap_setfilter(pd, &fcode) < 0)
		error("%s", pcap_geterr(pd));
	pcap_userdata = 0;
	(void)fprintf(stderr, "%s: listening on %s\n", program_name, device);
	if (pcap_loop(pd, cnt, raw_print, pcap_userdata) < 0) {
		(void)fprintf(stderr, "%s: pcap_loop: %s\n",
		    program_name, pcap_geterr(pd));
		exit(1);
	}
	pcap_close(pd);
	exit(0);
}

/* routine is executed on exit */
void program_ending(int signo)
{
	struct pcap_stat stat;

	if (pd != NULL && pcap_file(pd) == NULL) {
		(void)fflush(stdout);
		putc('\n', stderr);
		if (pcap_stats(pd, &stat) < 0)
			(void)fprintf(stderr, "pcap_stats: %s\n",
			    pcap_geterr(pd));
		else {
			(void)fprintf(stderr, "%d packets received by filter\n",
			    stat.ps_recv);
			(void)fprintf(stderr, "%d packets dropped by kernel\n",
			    stat.ps_drop);
		}
	}
	
	fprintf(stderr, "\n");
	fprintf(stderr, "%u broadcast packets received\n", num_broadcast_packets);
	fprintf(stderr, "%u ARP packets received\n", num_arp_packets);
	fprintf(stderr, "%u IP packets received\n", num_ip_packets);
	fprintf(stderr, "  %u ICMP packets received\n", num_icmp_packets);
	fprintf(stderr, "  %u UDP packets received\n", num_udp_packets);
	fprintf(stderr, "    %u DNS packets received\n", num_dns_packets);
	fprintf(stderr, "  %u TCP packets received\n", num_tcp_packets);
	fprintf(stderr, "    %u SMTP packets received\n", num_smtp_packets);
	fprintf(stderr, "    %u POP packets received\n", num_pop_packets);
	fprintf(stderr, "    %u IMAP packets received\n", num_imap_packets);
	fprintf(stderr, "    %u HTTP packets received\n", num_http_packets);

	exit(0);
}

/* Like default_print() but data need not be aligned */
void default_print_unaligned(register const u_char *cp, register u_int length)
{
	register u_int i, s;
	register int nshorts;

	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t\t\t");
		s = *cp++;
		(void)printf(" %02x%02x", s, *cp++);
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t\t\t");
		(void)printf(" %02x", *cp);
	}
}

/*
 * By default, print the packet out in hex.
 */
void default_print(register const u_char *bp, register u_int length)
{
	register const u_short *sp;
	register u_int i;
	register int nshorts;

	if ((long)bp & 1) {
		default_print_unaligned(bp, length);
		return;
	}
	sp = (u_short *)bp;
	nshorts = (u_int) length / sizeof(u_short);
	i = 0;
	while (--nshorts >= 0) {
		if ((i++ % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %04x", ntohs(*sp++));
	}
	if (length & 1) {
		if ((i % 8) == 0)
			(void)printf("\n\t");
		(void)printf(" %02x", *(u_char *)sp);
	}
}

void print_ascii(const u_char* p, u_int len, int offset) 
{
	int i = 0;
	for (i = 0; i < len; i++) {
		if (isprint(p[i + offset])) {
			putchar(p[i+offset]);
		}
	}
}

void smtp_print(const u_char* p, u_int len) 
{
	printf("SMTP\n");
	int payload_offset = 54;
	print_ascii(p, len, 54);
}

void pop_print(const u_char* p, u_int len) 
{
	printf("POP\n");
	int payload_offset = 54;
	print_ascii(p, len, 54);
}

void imap_print(const u_char* p, u_int len) 
{
	printf("IMAP\n");
	int payload_offset = 54;
	print_ascii(p, len, 54);
}

void http_print(const u_char* p, u_int len) 
{
	printf("HTTP\n");
	print_ascii(p, len, 66);
}

void udp_print(const u_char* p, u_int len) {
	udp_header_t* header = (struct udp_header_struct*)(p + 34);

	u_int src_port = ntohs(header->src_port);
	u_int dst_port = ntohs(header->dst_port);

	printf("UDP:\n");
	printf("  Source port: %u\n", src_port);
	printf("  Destination port: %u\n", dst_port);
	printf("  Length: %u\n", ntohs(header->len));
	printf("  Checksum: 0x%04X\n", ntohs(header->checksum));

	if(src_port == 53 || dst_port == 53) {
		num_dns_packets++;
	}
}


void tcp_print(const u_char* p, u_int len) {
	tcp_header_t* header = (struct tcp_header_struct*)(p + 34);

	u_int src_port = ntohs(header->src_port);
	u_int dst_port = ntohs(header->dst_port);

	printf("TCP:\n");
	printf("  Source port: %u\n", src_port);
	printf("  Destination port: %u\n", header->dst_port);
	printf("  Sequence number: 0x%04X\n", ntohl(header->seq_num));
	printf("  Acknowledgement number: 0x%04X\n", ntohl(header->ack_num));
	printf("  Header Length: %u\n", header->data_offset);

	printf("  flags:\n");
	printf("    NS: %u\n", header->ns);
	printf("    CWR: %u\n", header->cwr);
	printf("    ECE: %u\n", header->ece);
	printf("    URG: %u\n", header->urg);
	printf("    ACK: %u\n", header->ack);
	printf("    PSH: %u\n", header->psh);
	printf("    RST: %u\n", header->rst);
	printf("    SYN: %u\n", header->syn);
	printf("    FIN: %u\n", header->fin);

	printf("  Window size value: %u\n", ntohs(header->win_size));
	printf("  Checksum: 0x%04X\n", ntohs(header->checksum));
	printf("  Urgent pointer: %u\n", ntohs(header->urgent_p));

	if(src_port == 53 || dst_port == 53) {
		num_dns_packets++;
	} else if(src_port == 80 || dst_port == 80) {
		num_http_packets++;
		http_print(p, len);
	} else if(src_port == 143 || dst_port == 143) {
		num_imap_packets++;
		imap_print(p, len);
	} else if(src_port == 110 || dst_port == 110) {
		num_pop_packets++;
		pop_print(p, len);
	} else if(src_port == 25 || dst_port == 25) {
		num_smtp_packets++;
		stmp_print(p, len);
	}
}


void icmp_print(const u_char* p, u_int len) {
	icmp_header_t* header = (struct icmp_header_struct*)(p + 34);

	printf("ICMP:\n");
	printf("  Type: %u\n", header->type);
	printf("  Code: %u\n", header->code);
	printf("  Checksum: 0x%04X\n", ntohs(header->checksum));
	printf("  Identifier: 0x%04X\n", ntohs(header->id));
	printf("  Sequence number: 0x%04X\n", ntohs(header->sequence));
}


void ip_print(const u_char* p, u_int len) {
	int i;
	ip_header_t* header = (struct ip_header_struct*)(p + 14);

	printf("IP:\n");
	printf("  Version: %u\n", header->version);
	printf("  Header length: %u\n", header->header_len);
	printf("  Services field: 0x%02X\n", header->svc_field);
	printf("  Total length: %u\n", ntohs(header->total_len));
	printf("  Identification: 0x%04X\n", ntohs(header->id));
	printf("  Flags: 0x%04X\n", ntohs(header->flags));
	printf("  Time to live: %u\n", header->ttl);
	printf("  Protocol: %u\n", header->protocol);
	printf("  Header checksum: 0x%04X\n", ntohs(header->checksum));

	printf("  Source: ");
	for(i = 0; i < 3; i++) {
		printf("%u.", header->src[i]);
	}
	printf("%u\n", header->src[i]);

	printf("  Destination: ");
	for(i = 0; i < 3; i++) {
		printf("%u.", header->dst[i]);
	}
	printf("%u\n", header->dst[i]);	

	if(header->protocol == 1) { // icmp
		num_icmp_packets++;
		icmp_print(p, len);
	} else if(header->protocol == 6) { // tcp
		num_tcp_packets++;
		tcp_print(p, len);
	} else if(header->protocol == 17) { // udp
		num_udp_packets++;
		udp_print(p, len);
	}
}


void arp_print(const u_char* p, u_int len) {
	int i;
	uint16_t op;
	arp_header_t* header = (struct arp_header_struct*)(p + 14);

	printf("ARP:\n");
	printf("  Hardware type: %u\n", ntohs(header->h_type));
	printf("  Protocol type: 0x%04X\n", ntohs(header->p_type));
	printf("  Hardware size: %u\n", header->h_size);
	printf("  Protocol size: %u\n", header->p_size);

	op = ntohs(header->opcode);
	if(op == 1) {
		printf("  Opcode: request (%u)\n", op);
	} else if(op== 2) {
		printf("  Opcode: reply (%u)\n", op);
	} else {
		printf("  Opcode: %u\n", op);
	}
	
	printf("  Sender MAC address: ");
	for(i = 0; i < 5; i++) {
		printf("%02X:", header->snd_mac_addr[i]);
	}
	printf("%02X\n", header->snd_mac_addr[i]);

	printf("  Sender IP address: ");
	for(i = 0; i < 3; i++) {
		printf("%u.", header->snd_ip_addr[i]);
	}
	printf("%u\n", header->snd_ip_addr[i]);

	printf("  Target MAC address: ");
	for(i = 0; i < 5; i++) {
		printf("%02X:", header->tgt_mac_addr[i]);
	}
	printf("%02X\n", header->tgt_mac_addr[i]);

	printf("  Target IP address: ");
	for(i = 0; i < 3; i++) {
		printf("%u.", header->tgt_ip_addr[i]);
	}
	printf("%u\n", header->tgt_ip_addr[i]);	
}


void eth_print(const u_char* p, u_int len)
{
	uint16_t type = 0;	
	
	printf("\n\nEthernet\n");
	printf("  Destination: %02X:%02X:%02X:%02X:%02X:%02X\n", p[0], p[1], p[2], p[3], p[4], p[5]);
	printf("  Source: %02X:%02X:%02X:%02X:%02X:%02X\n", p[6], p[7], p[8], p[9], p[10], p[11]);
    
    
    // dst == FF:FF:FF:FF:FF:FF
    if(p[6] == 0xFF && p[7] == 0xFF && p[8] == 0xFF && p[9] == 0xFF && p[10] == 0xFF && p[11] == 0xFF){
    	num_broadcast_packets++;
    }
    
    type = p[12] * 256 + p[13];
    if(type <= 1500) {
    	printf("  Len: %u\n", type);
    } else if(type > 1536) {
    	printf("  Type: 0x%X\n", type);
    } 
    if(type == 0x800) {
    	num_ip_packets++;
    	printf("  Payload: IP\n");
    	ip_print(p, len);
    } else if(type == 0x806) {
    	num_arp_packets++;
    	printf("  Payload: ARP\n");
    	arp_print(p, len);
    }
}

/*
 *insert your code in this routine
 */
void raw_print(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
        u_int length = h->len;
        u_int caplen = h->caplen;

        eth_print(p, caplen);
        default_print(p, caplen);
        putchar('\n');
}

