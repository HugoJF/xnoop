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

/***********************
 * STATIC DECLARATIONS *
 ***********************/

#define MAX_PACKET_SIZE 65536
#define MIN_PACKET_SIZE 32 // update to 32 since 64 breaks ARP packets

#define MAX_FILTER_STACK 32

/***********
 * TYPEDEF *
 ***********/

typedef struct _ether_hdr {
    unsigned char ether_dhost[6];    // Destination address
    unsigned char ether_shost[6];    // Source address
    unsigned short ether_type;    // Type of the payload
} ether_hdr;

typedef struct _ip_hdr {
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
} ip_hdr;

typedef struct _arp_hdr {
    unsigned short htype;
    unsigned short ptype;
    unsigned char hlen;
    unsigned char plen;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned char sender_ip[4];
    unsigned char dest_mac[6];
    unsigned char dest_ip[4];
} arp_hdr;

typedef struct _udp_hdr {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned short length;
    unsigned short checksum;
} udp_hdr;

typedef struct _tcp_hdr {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned int seq_number;
    unsigned int ack_number;
    unsigned char offset:4;
    unsigned char reserved:3;
    unsigned short flags:9;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
} tcp_hdr;

typedef struct _icmp_hdr {
    unsigned short type;
    unsigned short code;
    unsigned int checksum;
} icmp_hdr;

/**********************
 * STARTUP PARAMETERS *
 **********************/

// How many packets should be read
int max_packets = 0;

// How many filters were passed as arguments
int filter_count = 0;

// Should address translations be skipped?
bool no_translation = false;

// How much information should be printed to screen
bool verbose = false;
bool verbose_extended = false;

/**********************
 * RUNTIME PARAMETERS *
 **********************/

// Read packet count
int packet_count = 0;

// Filter stack
unsigned long *stack;

// Where is the top of the stack
int stackTop = 0;

// List of filters
char **filters;

// Current headers to be filtered
ether_hdr *current_ether_hdr = NULL;
ip_hdr *current_ip_hdr = NULL;
arp_hdr *current_arp_hdr = NULL;

/***********
 * FILTERS *
 ***********/

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


/*******************
 * PARSE FUNCTIONS *
 *******************/

unsigned char *parse_ether_addr(char *filter) {
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

unsigned long parse_decimal(char *filter) {
    long int i = strtol(filter, NULL, 10);

    return (unsigned long) i;
}

unsigned long parse_hex(char *filter) {
    long int i = strtol(filter, NULL, 16);

    return (unsigned long) i;
}

/******************
 * PUSH FUNCTIONS *
 ******************/

void push_ether_addr(unsigned char ether[6]) {
    unsigned long i = 0;

    for (int j = 0; j < 6; ++j) {
        i += (ether[j]) << 8 * (5 - j);
    }

    stack[stackTop++] = i & 0xFFFFFFFFFFFF;
}

void push_ip_addr(unsigned int ip[4]) {
    unsigned long res = 0;

    for (int i = 0; i < 4; ++i) {
        res += (ip[i]) << 8 * (3 - i);
    }

    stack[stackTop++] = res & 0xFFFFFFFF;
}

void push_hex(unsigned int number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

void push_decimal(unsigned int number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

void push_ipproto() {
    stack[stackTop++] = current_ip_hdr->ip_proto;
}

void push_ipfrom() {
    if (current_ip_hdr) {
        push_ip_addr(current_ip_hdr->ip_src);
    } else {
        stack[stackTop++] = 0;
    }
}

void push_ipto() {
    if (current_ip_hdr) {
        push_ip_addr(current_ip_hdr->ip_dst);
    } else {
        stack[stackTop++] = 0;
    }
}

void push_ethertype() {
    stack[stackTop++] = current_ether_hdr->ether_type;
}

char *extract_data_from_hdr(ip_hdr *hdr) {
    unsigned int udp_data_len = current_ip_hdr->ip_len - sizeof(ip_hdr);
    char *udp_data = malloc(sizeof(char) * (udp_data_len));
    memcpy(udp_data + sizeof(ip_hdr), current_ip_hdr, udp_data_len);

    return udp_data;
}

void push_udptoport() {
    if (current_ip_hdr == NULL || current_ip_hdr->ip_proto != IPPROTO_UDP) {
        stack[stackTop++] = 0;
        return;
    }

    udp_hdr *udp_data = (udp_hdr *) extract_data_from_hdr(current_ip_hdr);
    stack[stackTop++] = udp_data->dst_port;

}

void push_udpfromport() {
    if (current_ip_hdr == NULL || current_ip_hdr->ip_proto != IPPROTO_UDP) {
        stack[stackTop++] = 0;
        return;
    }

    udp_hdr *udp_data = (udp_hdr *) extract_data_from_hdr(current_ip_hdr);
    stack[stackTop++] = udp_data->src_port;
}

void push_tcptoport() {
    if (current_ip_hdr == NULL || current_ip_hdr->ip_proto != IPPROTO_TCP) {
        stack[stackTop++] = 0;
        return;
    }

    tcp_hdr *tcp_data = (tcp_hdr *) extract_data_from_hdr(current_ip_hdr);
    stack[stackTop++] = tcp_data->dst_port;
}

void push_tcpfromport() {
    if (current_ip_hdr == NULL || current_ip_hdr->ip_proto != IPPROTO_TCP) {
        stack[stackTop++] = 0;
        return;
    }

    tcp_hdr *tcp_data = (tcp_hdr *) extract_data_from_hdr(current_ip_hdr);
    stack[stackTop++] = tcp_data->src_port;
}

void push_icmptype() {
    if (current_ip_hdr == NULL || current_ip_hdr->ip_proto != IPPROTO_ICMP) {
        stack[stackTop++] = 0;
        return;
    }

    icmp_hdr *icmp_data = (icmp_hdr *) extract_data_from_hdr(current_ip_hdr);
    stack[stackTop++] = icmp_data->type;
}

/**********************
 * CHECKING FUNCTIONS *
 **********************/

bool is_decimal(char *c) {
    int index = 0;
    int size = (int) strlen(c);

    while (isdigit(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

bool is_hex(char *c) {
    int index = 0;
    int size = (int) strlen(c);

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
    int size = (int) strlen(c);

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
    int size = (int) strlen(c);

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

/***************************
 *  FILTER SETUP FUNCTIONS *
 ***************************/

void set_ether_header(ether_hdr *ether_hdr) {
    current_ether_hdr = ether_hdr;
}

void set_ip_header(ip_hdr *ip_hdr) {
    current_ip_hdr = ip_hdr;
}

void set_arp_header(arp_hdr *arp_hdr) {
    current_arp_hdr = arp_hdr;
}

// Print the expected command line for the program
void print_usage() {
    printf("xnoop -i <interface> [options] [filter]\n");
    exit(1);
}

int process_parameter(int argi, char **argv) {
    // Since with need 'argi', the parameter value cannot be directly passed as argument
    char *arg = argv[argi];

    // If no parameters were passed
    if (arg == NULL) return 0;

    // Switch parameter flags
    if (strcmp("-c", arg) == 0) {
        max_packets = (int) strtol(argv[argi + 1], NULL, 10);
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

void process_parameters(int argc, char **argv) {
    // Check parameter count
    if (argc < 3)
        print_usage();

    // Check interface name
    if (strcmp(argv[1], "-i") != 0)
        print_usage();

    // Indexes used while processing a single argument
    int used = 0;
    // Where optinal parameters begin
    int index = 3;

    // Process arguments while 'process_parameter' is able to use parameters
    do {
        used = process_parameter(index, argv);
        index += used;
    } while (used != 0);

    // User feedback
    filter_count = argc - index;
    printf("Filters start at parameter index %d:%s\n", index, argv[index]);
    printf("Running with %d filters\n", filter_count);

    // Reorder filters into own array for readability
    filters = malloc(sizeof(char *) * filter_count);
    for (int i = 0; i < filter_count; ++i) {
        filters[i] = argv[index + i];
    }
}

void reset_stack() {
    stackTop = 0;
    for (int i = 0; i < MAX_FILTER_STACK; ++i) {
        stack[i] = 0;
    }
}

// TODO: move to correct section
bool streq(char *a, char *b) {
    return strcmp(a, b) == 0;
}

void run_filter(char *filter) {
    if (streq("udp", filter)) {
        run_udp_filter();
    } else if (streq("tcp", filter)) {
        run_tcp_filter();
    } else if (streq("icmp", filter)) {
        run_icmp_filter();
    } else if (streq("arp", filter)) {
        run_arp_filter();
    } else if (streq("ip", filter)) {
        run_ip_filter();
    } else if (streq("or", filter)) {
        run_or_filter();
    } else if (streq("and", filter)) {
        run_and_filter();
    } else if (streq("eq", filter) || streq("=", filter)) {
        run_eq_filter();
    } else if (streq("!", filter)) {
        run_not_filter();
    } else if (streq("+", filter)) {
        run_plus_filter();
    } else if (streq("-", filter)) {
        run_minus_filter();
    } else if (streq("*", filter)) {
        run_mult_filter();
    } else if (streq("/", filter)) {
        run_div_filter();
    } else if (streq("%", filter)) {
        run_mod_filter();
    } else if (streq("etherto", filter)) {
        push_ether_addr(current_ether_hdr->ether_dhost);
    } else if (streq("etherfrom", filter)) {
        push_ether_addr(current_ether_hdr->ether_shost);
    } else if (streq("ethertype", filter)) {
        push_ethertype();
    } else if (streq("ipto", filter)) {
        push_ipto();
    } else if (streq("ipfrom", filter)) {
        push_ipfrom();
    } else if (streq("ipproto", filter)) {
        push_ipproto();
    } else if (streq("udptoport", filter)) {
        push_udptoport();
    } else if (streq("udpfromport", filter)) {
        push_udpfromport();
    } else if (streq("tcptoport", filter)) {
        push_tcptoport();
    } else if (streq("tcpfromport", filter)) {
        push_tcpfromport();
    } else if (streq("icmptype", filter)) {
        push_icmptype();
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


void run_filters() {

    for (int i = 0; i < filter_count; ++i) {
//        printf("Running filter: %s\n", filters[i]);
        run_filter(filters[i]);
    }

    if (filter_count == 0) {
        stack[0] = 1;
    }
}

// Bind a socket to a interface
int bind_iface_name(int fd, char *iface_name) {
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, (socklen_t) strlen(iface_name));
}

bool is_filtered() {
    reset_stack();
    run_filters();

    return stack[0] == 0;
}

char *ether_addr_to_string(unsigned char *addr) {
    char *str = malloc(sizeof(char) * 17);

    // TODO: check ntohs
    sprintf(str, "%02x:%02x:%02x:%02x:%02x:%02x",
            (addr[0]),
            (addr[1]),
            (addr[2]),
            (addr[3]),
            (addr[4]),
            (addr[5])
    );

    return str;
}

char *get_ether_type_name(unsigned int type) {
    switch (type) {
        case ETH_P_ARP:
            return "ARP";
        case ETH_P_RARP:
            return "RARP";
        case ETH_P_IP:
            return "IPv4";
        case ETH_P_IPV6:
            return "IPv6";
        default:
            return "Unknown";
    }
}

char *get_make_from_ether_addr(unsigned int *addr) {
    return "Intel";
}

void print_ether_hdr(ether_hdr *hdr, int data_size) {

    int order = packet_count;
    int size = data_size;
    int type_number = hdr->ether_type;
    char *type_name = get_ether_type_name(ntohs(hdr->ether_type));
    char *dst_addr = ether_addr_to_string(hdr->ether_dhost);
    char *src_addr = ether_addr_to_string(hdr->ether_shost);
    char *make = get_make_from_ether_addr(hdr->ether_shost);

    printf("ETHER:  ----- Ethernet Header -----\n"
           "ETHER:\n"
           "ETHER:  Packet %d\n"
           "ETHER:  Packet size = %d bytes\n"
           "ETHER:  Destination = %s, (broadcast)\n"
           "ETHER:  Source      = %s, %s\n"
           "ETHER:  Ethertype = %x (%s)\n"
           "ETHER:\n",
            /* Packet      */ order,
            /* Packet size */ size,
            /* Destination */ dst_addr,
            /* Source      */ src_addr, make,
            /* Ethertype   */ type_number, type_name
    );

    extra
}

// Break this function to implement the functionalities of your packet analyser
void process(unsigned char *packet, int len) {
    // Check if frame is valid
    if (len == 0)
        return;

    // Cast packet data to Ethernet Header struct
    ether_hdr *eth = (ether_hdr *) packet;

    // Allocate and copy data from Ethernet header
    unsigned char *data = malloc(sizeof(unsigned char) * (len - sizeof(ether_hdr)));
    memcpy(data, packet + sizeof(ether_hdr), sizeof(unsigned char) * (len - sizeof(ether_hdr)));

    // Globally set current Ethernet header to be used to run filters
    set_ether_header(eth);

    if (eth->ether_type == htons(0x0800)) {
        ip_hdr *ip = (ip_hdr *) data;

        set_arp_header(NULL);
        set_ip_header(ip);
    } else if (eth->ether_type == htons(0x0806)) {
        arp_hdr *arp = (arp_hdr *) data;

        set_arp_header(arp);
        set_ip_header(NULL);
    }

    if (!is_filtered()) {
        print_ether_hdr(current_ether_hdr, len);

        fflush(stdout);
    }
}

int main(int argc, char **argv) {
    int n;
    int sockfd;
    unsigned char *packet_buffer;
    stack = malloc(sizeof(long) * MAX_FILTER_STACK);

    // Read parameters and filters
    process_parameters(argc, argv);

    // Building socket
    if ((sockfd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
        perror("Building socket");
        exit(errno);
    }

    // Bind socket to interface by name
    if (bind_iface_name(sockfd, argv[2]) < 0) {
        perror("Binding socket");
        exit(errno);
    }

    // Allocate packet buffer
    packet_buffer = malloc(MAX_PACKET_SIZE);
    if (!packet_buffer) {
        printf("Could not allocate a packet buffer\n");
        exit(1);
    }

    // Read `max_packets` packets
    while (packet_count++ < max_packets) {

        if ((n = recv(sockfd, packet_buffer, MAX_PACKET_SIZE, 0)) < 0) {
            perror("Reading packet");
            exit(errno);
        }
        printf(".");
        process(packet_buffer, n);
    }

    free(packet_buffer);
    close(sockfd);
    printf("Ended\n");
    return 0;
}