#include <errno.h>
#include <stdio.h>
#include <stdbool.h>
#include <netdb.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/ethernet.h>

#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 64

#define MAX_FILTER_STACK 32

struct ether_hdr {
    unsigned char	ether_dhost[6];	// Destination address
    unsigned char	ether_shost[6];	// Source address
    unsigned short	ether_type;	// Type of the payload
};

struct ip_hdr {
    unsigned char 	ip_v:4;		// IP Version
    unsigned char   ip_hl:4;	// Header length
    unsigned char	ip_tos;		// Type of service
    unsigned short	ip_len;		// Datagram Length
    unsigned short	ip_id;		// Datagram identifier
    unsigned short	ip_offset;	// Fragment offset
    unsigned char	ip_ttl;		// Time To Live
    unsigned char	ip_proto;	// Protocol
    unsigned short	ip_csum;	// Header checksum
    unsigned int	ip_src;		// Source IP address
    unsigned int	ip_dst;		// Destination IP address
};

int max_packets = 0;
int filters_index = 0;
bool no_translation = false;
bool verbose = false;
bool verbose_extended = false;

int packet_count = 0;


int process_parameters(int argc, char **argv);

// Bind a socket to a interface
int bind_iface_name(int fd, char *iface_name)
{
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name));
}

// Print an Ethernet address
void print_eth_address(char *s, unsigned char *eth_addr)
{
    printf("%s %02X:%02X:%02X:%02X:%02X:%02X", s,
           eth_addr[0], eth_addr[1], eth_addr[2],
           eth_addr[3], eth_addr[4], eth_addr[5]);
}

// Break this function to implement the functionalities of your packet analyser
void doProcess(unsigned char* packet, int len) {
    if(!len || len < MIN_PACKET_SIZE)
        return;

    struct ether_hdr* eth = (struct ether_hdr*) packet;

    print_eth_address("\nDst =", eth->ether_dhost);
    print_eth_address(" Src =", eth->ether_shost);
    printf(" Ether Type = 0x%04X Size = %d", ntohs(eth->ether_type), len);


    if(eth->ether_type == htons(0x0800)) {
        //IP

        //...
    } else if(eth->ether_type == htons(0x0806)) {
        //ARP

        //...
    }
    fflush(stdout);
}

// Print the expected command line for the program
void print_usage()
{
    printf("\nxnoop -i <interface> [options] [filter]\n");
    exit(1);
}

// main function
int main(int argc, char** argv) {
    int		n;
    int		sockfd;
    socklen_t	saddr_len;
    struct sockaddr	saddr;
    unsigned char	*packet_buffer;
    long *stack = malloc(sizeof(long) * MAX_FILTER_STACK);


    process_parameters(argc, argv);

    saddr_len = sizeof(saddr);

    // Create socket
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if(sockfd < 0) {
        fprintf(stderr, "ERROR: %s\n", strerror(errno));
        exit(1);
    }

    // Bind interface by name
    if (bind_iface_name(sockfd, argv[2]) < 0) {
        perror("Server-setsockopt() error for SO_BINDTODEVICE");
        printf("%s\n", strerror(errno));
        close(sockfd);
        exit(1);
    }

    // Allocate packet buffer
    packet_buffer = malloc(MAX_PACKET_SIZE);
    if (!packet_buffer) {
        printf("\nCould not allocate a packet buffer\n");
        exit(1);
    }

    while(packet_count++ < max_packets) {
        n = recvfrom(sockfd, packet_buffer, MAX_PACKET_SIZE, 0, &saddr, &saddr_len);
        if(n < 0) {
            fprintf(stderr, "ERROR: %s\n", strerror(errno));
            exit(1);
        }
        doProcess(packet_buffer, n);
    }

    free(packet_buffer);
    close(sockfd);

    return 0;
}

int process_parameter(int argi, char **argv) {
    char *arg = argv[argi];
    if (strcmp("-c", arg) == 0) {
        max_packets = atoi(argv[argi + 1]);
        printf("-c = Capturing only %d packets.\n", max_packets);
        return 2;
    } else if (strcmp("-n", arg) == 0) {
        no_translation = true;
        printf("-n = No translation mode enabled.\n");
        return 1;
    } else if (strcmp("-v", arg) == 0 ){
        printf("-v = Verbose mode enabled\n");
        verbose = true;
        return 1;
    } else if (strcmp("-V", arg) == 0) {
        printf("-V = Extended verbode mode enabled\n");
        verbose = true;
        verbose_extended = true;
        return 1;
    } else {
        return 0;
    }
}


int process_parameters(int argc, char **argv) {
    // Check count
    if (argc < 3)
        print_usage();

    // Check interface name
    if (strcmp(argv[1], "-i") != 0)
        print_usage();

    int tmp = 0;
    int index = 3;

    // Run optional parameters
    do {
        tmp = process_parameter(index, argv);
        index += tmp;
    } while (tmp != 0);

    // Info
    printf("Filters start at parameter index %d:%s\n", index, argv[index]);
    filters_index = index;
}
