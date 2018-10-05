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
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <ctype.h>


#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 32 // update to 32 since 64 breaks ARP packets

#define MAX_FILTER_STACK 32

struct ether_hdr {
    unsigned char ether_dhost[6];    // Destination address
    unsigned char ether_shost[6];    // Source address
    unsigned short ether_type;    // Type of the payload
};

struct ip_hdr {
    unsigned char ip_v:4;        // IP Version
    unsigned char ip_hl:4;    // Header length
    unsigned char ip_tos;        // Type of service
    unsigned short ip_len;        // Datagram Length
    unsigned short ip_id;        // Datagram identifier
    unsigned short ip_offset;    // Fragment offset
    unsigned char ip_ttl;        // Time To Live
    unsigned char ip_proto;    // Protocol
    unsigned short ip_csum;    // Header checksum
    unsigned int ip_src;        // Source IP address
    unsigned int ip_dst;        // Destination IP address
};

struct arp_hdr {
    unsigned short htype;
    unsigned short ptype;
    unsigned char  hlen;
    unsigned char  plen;
    unsigned short opcode;
    unsigned char  sender_mac[6];
    unsigned char  sender_ip[4];
    unsigned char  dest_mac[6];
    unsigned char  dest_ip[4];
};

int max_packets = 0;
int filter_count = 0;
bool no_translation = false;
bool verbose = false;
bool verbose_extended = false;


int packet_count = 0;
unsigned long *stack;
int stackTop = 0;
char **filters;
struct ether_hdr *current_ether_hdr = NULL;
struct ip_hdr *current_ip_hdr = NULL;
struct arp_hdr *current_arp_hdr = NULL;


int process_parameters(int argc, char **argv);

bool packet_filter(struct ether_hdr *ether_hdr, struct ip_hdr *ip_hdr);

void run_udp_filter();

void run_tcp_filter();

void run_icmp_filter();

void run_arp_filter();

void run_ip_filter();

void run_or_filter();

void run_and_filter();

void run_eq_filter();

void run_not_filter();

void run_plus_filter();

void run_minus_filter();

void run_mult_filter();

void run_div_filter();

void run_mod_filter();

unsigned long parse_decimal(char *filter);
unsigned long parse_hex(char *filter);
int * parse_ip_addr(char *filter);
unsigned char * parse_ether_addr(char *filter);

void push_decimal(unsigned int number);
void push_hex(unsigned int number);
void push_ip_addr(int ip[4]);
void push_ether_addr(unsigned char ether[6]);



bool is_decimal(char *c) {
    int index = 0;
    int size = strlen(c);

    while (isdigit(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

bool is_hex(char *c) {
    int index = 0;
    int size = strlen(c);

    if (c[index] == '0' && index < size) {
        index++;
    }

    if (c[index] == 'x' && index < size) {
        index++;
    }

    while (isalnum(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

bool is_ip_addr(char *c) {
    int index = 0;
    int size = strlen(c);

    for (int i = 0; i < 3; ++i) {
        while (isdigit(c[index]) && index < size) {
            index++;
        }
        if (c[index] == '.' && index < size) {
            index++;
        }
    }
    while (isdigit(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

bool is_ether_addr(char *c) {
    int index = 0;
    int size = strlen(c);

    for (int i = 0; i < 5; ++i) {
        while (isalnum(c[index]) && index < size) {
            index++;
        }
        if (c[index] == ':' && index < size) {
            index++;
        }
    }

    while (isalnum(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

void set_ether_header(struct ether_hdr *ether_hdr) {
    current_ether_hdr = ether_hdr;
}

void set_ip_header(struct ip_hdr *ip_hdr) {
    current_ip_hdr = ip_hdr;
}

void set_arp_header(struct arp_hdr *arp_hdr) {
    current_arp_hdr = arp_hdr;
}

// Bind a socket to a interface
int bind_iface_name(int fd, char *iface_name) {
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, strlen(iface_name));
}

// Print an Ethernet address
void print_eth_address(char *s, unsigned char *eth_addr) {
    printf("%s %02X:%02X:%02X:%02X:%02X:%02X", s,
           eth_addr[0], eth_addr[1], eth_addr[2],
           eth_addr[3], eth_addr[4], eth_addr[5]);
}

// Break this function to implement the functionalities of your packet analyser
void process(unsigned char *packet, int len) {
    if (!len)
        return;

    struct ether_hdr *eth = (struct ether_hdr *) packet;

    unsigned char *data = malloc(sizeof(unsigned char) * (len - sizeof(struct ether_hdr)));

    memcpy(data, packet + 14, sizeof(unsigned char) * (len - sizeof(struct ether_hdr)));

    if (eth->ether_type == htons(0x0800)) {
        struct ip_hdr *ip = (struct ip_hdr *) data;

        set_arp_header(NULL);
        set_ip_header(ip);
    } else if (eth->ether_type == htons(0x0806)) {
        struct arp_hdr *arp = (struct arp_hdr *) data;

        set_arp_header(arp);
        set_ip_header(NULL);
    }

    // TODO: pass IPv4 header
    if (packet_filter(eth, NULL) == false) {
        return;
    }

    print_eth_address("\nDst =", eth->ether_dhost);
    print_eth_address(" Src =", eth->ether_shost);
    printf(" Ether Type = 0x%04X Size = %d\n", ntohs(eth->ether_type), len);

    fflush(stdout);
}

// TODO: needed? filter runs should overwrite values
void reset_stack() {
    stackTop = 0;
    for (int i = 0; i < MAX_FILTER_STACK; ++i) {
        stack[0] = 0;
    }
}

void run_filter(char *filter) {
    if (strcmp("udp", filter) == 0) {
        run_udp_filter();
    } else if (strcmp("tcp", filter) == 0) {
        run_tcp_filter();
    } else if (strcmp("icmp", filter) == 0) {
        run_icmp_filter();
    } else if (strcmp("arp", filter) == 0) {
        run_arp_filter();
    } else if (strcmp("ip", filter) == 0) {
        run_ip_filter();
    } else if (strcmp("or", filter) == 0) {
        run_or_filter();
    } else if (strcmp("and", filter) == 0) {
        run_and_filter();
    } else if (strcmp("eq", filter) == 0 || strcmp("=", filter) == 0) {
        run_eq_filter();
    } else if (strcmp("!", filter) == 0) {
        run_not_filter();
    } else if (strcmp("+", filter) == 0) {
        run_plus_filter();
    } else if (strcmp("-", filter) == 0) {
        run_minus_filter();
    } else if (strcmp("*", filter) == 0) {
        run_mult_filter();
    } else if (strcmp("/", filter) == 0) {
        run_div_filter();
    } else if (strcmp("%", filter) == 0) {
        run_mod_filter();
    } else if (strcmp("etherto", filter) == 0) {
        push_ether_addr(current_ether_hdr->ether_dhost);
    } else if (strcmp("etherfrom", filter) == 0) {
        push_ether_addr(current_ether_hdr->ether_shost);
    } else if (strcmp("ethertype", filter) == 0) {
        stack[stackTop++] = current_ether_hdr->ether_type;
    } else if(strcmp("ipto", filter) == 0) {
        if(current_ip_hdr){
            push_ip_addr(current_ip_hdr->ip_dst);
        } else {
            stack[stackTop++] = 0;
        }
    } else if (strcmp("ipfrom", filter) == 0) {
        if(current_ip_hdr){
            push_ip_addr(current_ip_hdr->ip_src);
        } else {
            stack[stackTop++] = 0;
        }
    } else if (strcmp("ipproto", filter) == 0) {
        stack[stackTop++] = current_ip_hdr->ip_proto;
    } else if (is_decimal(filter)) {
        push_decimal(parse_decimal(filter));
    } else if (is_hex(filter)) {
        push_hex(parse_hex(filter));
    } else if (is_ip_addr(filter)) {
        push_ip_addr(parse_ip_addr(filter));
    } else if (is_ether_addr(filter)) {
        push_ether_addr(parse_ether_addr(filter));
    } else {
        printf("Could not find filter: %s\n", filter);
        exit(1);
    }
}

void push_ether_addr(unsigned char ether[6]) {
    unsigned long i = 0;

    for (int j = 0; j < 6; ++j) {
        i += (ether[j]) << 8 * (5 - j);
    }

    stack[stackTop++] = i & 0xFFFFFFFFFFFF;
}

unsigned char * parse_ether_addr(char *filter) {
    unsigned char *ether = malloc(sizeof(unsigned char) * 6);
    char *copy = malloc(sizeof(char) * (strlen(filter) + 1));
    strcpy(copy, filter);


    ether[0] = (unsigned char) strtol(strtok(copy, ":"), NULL, 16);
    for (int j = 1; j < 6; ++j) {
        ether[j] = (unsigned char) strtol(strtok(NULL, ":"), NULL, 16);
    }



    return (unsigned char *) ether;
}

int *parse_ip_addr(char *filter) {
    int *ipp = malloc(sizeof(int) * 4);
    char **ip = malloc(sizeof(char *) * 4);
    char *copy = malloc(sizeof(char) * (strlen(filter) + 1));
    strcpy(copy, filter);

    // Split IP String
    ip[0] = strtok(copy, ".");
    for (int i = 1; i < 4; ++i) {
        ip[i] = strtok(NULL, ".");
    }

    // Parse to int
    for (int i = 0; i < 4; ++i) {
        ipp[i] = atoi(ip[i]);
    }

    // Return IP number array
    return ipp;
}

void push_ip_addr(int ip[4]) {
    unsigned long res = 0;

    for (int i = 0; i < 4; ++i) {
        res += ((unsigned int) ip[i]) << 8 * (3 - i);
    }

    stack[stackTop++] = res & 0xFFFFFFFF;
}

void push_hex(unsigned int number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

unsigned long parse_hex(char *filter) {
    long int i = strtol(filter, NULL, 16);

    return (unsigned long) i;
}

void push_decimal(unsigned int number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

unsigned long parse_decimal(char *filter) {
    long int i = strtol(filter, NULL, 10);

    return (unsigned long) i;
}

void run_mod_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] % stack[stackTop - 1]);
    stackTop--;
}

void run_div_filter() {
    if (stack[stackTop - 1] == 0) {
        stack[stackTop - 2] = (stack[stackTop - 2] / stack[stackTop - 1]);
    } else {
        stack[stackTop - 2] = 0;
    }
    stackTop--;
}

void run_mult_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] * stack[stackTop - 1]);
    stackTop--;
}

void run_minus_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] - stack[stackTop - 1]);
    stackTop--;
}

void run_plus_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] + stack[stackTop - 1]);
    stackTop--;
}

void run_not_filter() { stack[stackTop - 1] = (stack[stackTop - 1] != 0); }

void run_eq_filter() {
//    printf("%lu == %lu ? ", stack[stackTop - 2], stack[stackTop - 1]);
    stack[stackTop - 2] = (stack[stackTop - 2] == stack[stackTop - 1]);
//    printf("Result: %lu\n", stack[stackTop - 2]);
    stackTop--;
}

void run_and_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] && stack[stackTop - 1]);
    stackTop--;
}

void run_or_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] || stack[stackTop - 1]);
    stackTop--;
}

void run_ip_filter() {
    stack[stackTop++] = current_ether_hdr != NULL && current_ether_hdr->ether_type == htons(ETH_P_IP);
}

void run_arp_filter() {
    stack[stackTop++] = current_ether_hdr != NULL && current_ether_hdr->ether_type == htons(ETH_P_ARP);
}

void run_icmp_filter() {
    stack[stackTop++] = current_ip_hdr != NULL && current_ip_hdr->ip_proto == htons(IPPROTO_ICMP);
}

void run_tcp_filter() { stack[stackTop++] = current_ip_hdr != NULL && current_ip_hdr->ip_proto == htons(IPPROTO_TCP); }

void run_udp_filter() { stack[stackTop++] = current_ip_hdr != NULL && current_ip_hdr->ip_proto == htons(IPPROTO_UDP); }

void run_filters() {

    for (int i = 0; i < filter_count; ++i) {
//        printf("Running filter: %s\n", filters[i]);
        run_filter(filters[i]);
    }

    if (filter_count == 0) {
        stack[0] = 1;
    }
}


bool packet_filter(struct ether_hdr *ether_hdr, struct ip_hdr *ip_hdr) {
    reset_stack();
    set_ether_header(ether_hdr);
    set_ip_header(ip_hdr);
    run_filters();
    return stack[0] == 1;
}


// Print the expected command line for the program
void print_usage() {
    printf("\nxnoop -i <interface> [options] [filter]\n");
    exit(1);
}

// main function
int main(int argc, char **argv) {
    int n;
    int sockfd;
    socklen_t saddr_len;
    struct sockaddr saddr;
    unsigned char *packet_buffer;
    stack = malloc(sizeof(long) * MAX_FILTER_STACK);

    process_parameters(argc, argv);


    saddr_len = sizeof(saddr);

    // Create socket
    sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (sockfd < 0) {
        fprintf(stderr, "ERROR socket(): %s\n", strerror(errno));
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

    while (packet_count++ < max_packets) {

        n = recv(sockfd, packet_buffer, MAX_PACKET_SIZE, 0);
        if (n < 0) {
            fprintf(stderr, "ERROR recvfrom: %s\n", strerror(errno));
            exit(1);
        }
        process(packet_buffer, n);
    }

    free(packet_buffer);
    close(sockfd);
    printf("Ended\n");
    return 0;
}

int process_parameter(int argi, char **argv) {
    char *arg = argv[argi];

    if (arg == NULL) return 0;

    if (strcmp("-c", arg) == 0) {
        max_packets = atoi(argv[argi + 1]);
        printf("-c = Capturing only %d packets.\n", max_packets);
        return 2;
    } else if (strcmp("-n", arg) == 0) {
        no_translation = true;
        printf("-n = No translation mode enabled.\n");
        return 1;
    } else if (strcmp("-v", arg) == 0) {
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
    filter_count = argc - index;
    printf("Filters start at parameter index %d:%s\n", index, argv[index]);
    printf("Running with %d filters\n", filter_count);
    filters = malloc(sizeof(char *) * filter_count);
    for (int i = 0; i < filter_count; ++i) {
        filters[i] = argv[index + i];
    }
}
