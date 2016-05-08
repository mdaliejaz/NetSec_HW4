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
#include <fcntl.h>

#define PROMISC 1
#define READ_TIME_OUT 0
#define SIZE_ETHERNET 14
#define IP_SIZE 16
#define PACKET_SIZE 8192
#define MAX_ARRAY_SIZE 1000

/* Ethernet header */
struct ethernet_header {
	u_char ether_dhost[ETHER_ADDR_LEN];
	u_char ether_shost[ETHER_ADDR_LEN];
	u_short ether_type;
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

/* DNS answer structure */
struct dns_answer {
	// u_int16_t
	char *name;
	char type[2];
	char class[2];
	char ttl[4];
	char rd_length[2];
	char *r_data;
};


static int start_db_index = 0;
static int end_db_index = -1;
static int array_size = 0;

/* Link list node for file options */
struct node {
	u_short id;
	int list_size;
	char ip[20][32];
	struct node *next;
};



/* The callback function for pcap_loop */
void dns_detect(struct node *database, const struct pcap_pkthdr *header, const u_char *packet)
{
	struct ethernet_header *ether;
	struct iphdr *ip;
	struct udphdr *udp, *reply_udp_hdr;
	struct ip *reply_ip_hdr;
	struct dns_question question;
	struct dns_answer answer;
	struct dns_header *dns_hdr;
	char src_ip[IP_SIZE], dst_ip[IP_SIZE];
	unsigned int ip_header_size;
	u_int16_t port;
	char request[150], *domain_name;
	char reply_packet[PACKET_SIZE];
	int size, i = 1, j = 0, k;
	unsigned int reply_packet_size;
	char spoof_ip[32], *reply;
	unsigned char split_ip[4];
	struct in_addr dest, src;
	int spoof_it = 0;
	int attack_detected = 0;
	char *new_ip;
	int matched, curr_index, possible_attack;
	char new_ip_list[20][32];
	char IP[100];
	int id_found;
	char *temp;
	char *hex_id;
	int epoch_time;				/* for calculating time for packet */
	time_t epoch_time_as_time_t;
	struct tm * timeinfo;
	int index_in_db;

	/* define ethernet header */
	ether = (struct ethernet_header*)(packet);
	// ip = (struct iphdr*)(((char*) ether) + sizeof(struct ethernet_header));
	ip = (struct iphdr*)(((char*)packet) + 14);

	/* get cleaned up IPs */
	src.s_addr = ip->saddr;
	dest.s_addr = ip->daddr;
	sprintf(src_ip, "%s", inet_ntoa(src));
	sprintf(dst_ip, "%s", inet_ntoa(dest));

	/* udp header */
	ip_header_size = ip->ihl * 4;
	udp = (struct udphdr*)(((char*) ip) + ip_header_size);

	/* dns header */
	dns_hdr = (struct dns_header*)(((char*) udp) + sizeof(struct udphdr));

	/* start of question */
	question.qname = ((char *)dns_hdr + 12);

	/*
	 * parse domain name
	 * [3]www[7]example[3]com -> www.example.com
	 */
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

	char *answer_start = (char *)question.qname + j + 6;

	char identifier[100];
	char str[2];
	u_short id = *((u_short *)dns_hdr->id);
	hex_id = dns_hdr->id;
	sprintf(identifier, "%hu", *((u_short *)dns_hdr->id));
	possible_attack = 0;
	k = 0;
	for (i = 0; i < htons(*((u_short *)(dns_hdr->ancount))); i++) {
		u_short type = ((u_short *)(answer_start + 2))[0];
		u_short class = ((u_short *)(answer_start + 4))[0];
		u_short resp_size = ((u_short *)(answer_start + 10))[0];

		// printf("Type: %d\n", htons(type));
		// printf("Class: %d\n", htons(class));
		// printf("resp size %d\n", htons(resp_size));

		int ip_exists = 0;
		id_found = 0;

		if (htons(type) == 1) {
			u_int IPi = ((u_int *)(answer_start + 12))[0];
			sprintf(IP, "%u.%u.%u.%u", ((u_char *)(&IPi))[0], ((unsigned char *)(&IPi))[1], ((unsigned char *)(&IPi))[2], ((unsigned char *)(&IPi))[3]);

			// printf("***id = %hu\n", id);
			// add to db
			for (i = 0; i < array_size; i++) {
				if (id == database[i].id) {
					index_in_db = i;
					possible_attack = 1;
					id_found = 1;
				}
			}

			strcpy(new_ip_list[k++], IP);

			answer_start = answer_start + 16;
		} else {
			answer_start = answer_start + 12 + htons(resp_size);
		}


	}

	if (id_found == 0) {
		for (i = 0; i < k; i++) {
			database[array_size].id = id;
			strcpy(database[array_size].ip[i], new_ip_list[i]);
		}
		database[array_size].list_size = k;
		array_size += 1;
	}

	if (possible_attack == 1) {
		epoch_time = header->ts.tv_sec;
		epoch_time_as_time_t = epoch_time;
		timeinfo = localtime(&epoch_time_as_time_t);

		printf("\nDNS poisoning attempt!!!\n");
		printf("Timestamp: %s", asctime(timeinfo));
		printf("TXID: 0x");
		printf("%x", (int)(*(unsigned char*)(hex_id)));
		printf("%x\t", (int)(*(unsigned char*)(hex_id + 1)));
		printf("Request: %s\n", request);
		printf("Answer1 [");
		for(i = 0; i< database[index_in_db].list_size; i++) {
			if(i+1 == database[index_in_db].list_size) {
				printf("%s", database[index_in_db].ip[i]);
			} else {
				printf("%s, ", database[index_in_db].ip[i]);
			}
		}
		printf("]\n");
		printf("Answer2 [");
		for(i = 0; i< k; i++) {
			if(i+1 == k) {
				printf("%s", new_ip_list[i]);
			} else {
				printf("%s, ", new_ip_list[i]);
			}
		}
		printf("]\n");
	}
}

int main(int argc, char *argv[])
{
	char *dev = NULL;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct bpf_program fp;
	char *bpf_filter_exp;			/* The input BPF filter expression */
	char *filter_exp;				/* Final filter expression to be used */
	bpf_u_int32 net;
	bpf_u_int32 mask;
	pcap_t *handle;					/* packet capture handle */
	int interface_provided = 0;
	int read_file = 0;
	char *dns_filter = "udp and src port 53";	/* static DNS filter */
	int bpf_filter = 0;
	int option = 0;
	char *file_name;
	// struct node *head, *current, *free_this;
	// char *line = NULL;
	// size_t len = 0;
	// ssize_t read;
	// char delimiter[] = " \t\n";
	// char *token;
	// char spoof_ip[32];
	// struct node *database;
	struct node database[MAX_ARRAY_SIZE];


	memset(errbuf, 0, PCAP_ERRBUF_SIZE);

	/* Parse the command line arguments */
	while ((option = getopt(argc, argv, "i:r:h")) != -1) {
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
		case 'r':
			if (read_file) {
				printf("You should provide only one file. Multiple files "
				       "are not supported.\n");
				exit(EXIT_FAILURE);
			}
			file_name = optarg;
			read_file = 1;
			break;
		case 'h':
			printf("help: dnsinject [-i interface] [-f hostnames] <expression>\n"
			       "-i  Listen on network device <interface> "
			       "(e.g., eth0). If not specified, dnsinject selects the default "
			       "interface to listen on.\n-f  Spoof only the domains mentioned "
			       "in the given file. If no file is provided all the DNS requests "
			       "coming to the attacker will be spoofed\n<expression> is a BPF "
			       "filter that specifies a subset of the traffic to be monitored. "
			       "This option is useful for targeting a single or a set of "
			       "particular victims\n");
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

	if (read_file == 1) {
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

	handle = pcap_open_live(dev, BUFSIZ, PROMISC, READ_TIME_OUT, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
		goto free_list;
	} else {
		printf("Listening on device: %s\n\n", dev);
	}

	/* Generate final BPF filter string */
	if (bpf_filter == 1) {
		filter_exp = malloc(strlen(dns_filter) + strlen(bpf_filter_exp) + 6);
		strcpy(filter_exp, dns_filter);
		strcat(filter_exp, " and ");
		strcat(filter_exp, bpf_filter_exp);
	} else {
		filter_exp = malloc(strlen(dns_filter) + 1);
		strcpy(filter_exp, dns_filter);
	}

	/* compile the program */
	if (pcap_compile(handle, &fp, filter_exp, 0, 0) == -1) {
		fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp,
		        pcap_geterr(handle));
		goto free_filter;
	}

	/* apply the filter */
	if (pcap_setfilter(handle, &fp) == -1) {
		fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp,
		        pcap_geterr(handle));
		goto free_filter;
	}

	/* set our callback function with infinite pcap_loop */
	pcap_loop(handle, -1, (pcap_handler)dns_detect, (u_char *)database);

	/* clean up */
	pcap_freecode(&fp);
	pcap_close(handle);

free_filter:
	free(filter_exp);
free_list:
// 	current = head;
// 	while (current != NULL) {
// 		free_this = current;
// 		current = current->next;
// 		free(free_this);
// 	}
	return 0;
}
