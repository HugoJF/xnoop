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
#include <signal.h>

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
    unsigned short ip_flags:3;
    unsigned short ip_offset:13;    // Fragment offset
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
    unsigned int sender_ip;
    unsigned char dest_mac[6];
    unsigned int dest_ip;
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

// Accept packets
int accepted_packets = 0;

// How many packets were rejected in a row
int sequential_rejected_packets= 0;

// Filter stack
unsigned long *stack;

// Where is the top of the stack
int stackTop = 0;

// List of filters
char **filters;

// Current headers to be filtered
ether_hdr *current_ether_hdr = NULL;
long current_ether_hdr_len = 0;

// Caches to avoid helper functions re-calculating stuff
unsigned char *current_network_data = NULL;  // ARP/IP
unsigned char *current_transport_data = NULL; // TCP/UDP


/**************************
 * HEADER DATA EXTRACTORS *
 **************************/


unsigned char *extract_data_from_hdr(unsigned char *hdr, unsigned int hdr_size, long data_len, unsigned int hdr_tail) {
    unsigned int udp_data_len = ((unsigned int) data_len) - hdr_size - hdr_tail;
    unsigned char *udp_data = malloc(sizeof(unsigned char) * (udp_data_len - hdr_tail));

    memcpy(udp_data, hdr + hdr_size, udp_data_len);

    return udp_data;
}

unsigned char *extract_data_from_eth_hdr(unsigned char *hdr, long data_len) {
    return extract_data_from_hdr(hdr, sizeof(ether_hdr), data_len, 0);
}

unsigned char *extract_data_from_arp_hdr(unsigned char *hdr, long data_len) {
    return extract_data_from_hdr(hdr, sizeof(arp_hdr), data_len, 0);
}

unsigned char *extract_data_from_ip_hdr(unsigned char *hdr, long data_len) {
    return extract_data_from_hdr(hdr, sizeof(ip_hdr), data_len, 0);
}

unsigned char *extract_data_from_tcp_hdr(unsigned char *hdr, long data_len) {
    return extract_data_from_hdr(hdr, sizeof(tcp_hdr), data_len, 0);
}

unsigned char *extract_data_from_udp_hdr(unsigned char *hdr, long data_len) {
    return extract_data_from_hdr(hdr, sizeof(udp_hdr), data_len, 0);
}

unsigned char *extract_data_from_icmp_hdr(unsigned char *hdr, long data_len) {
    return extract_data_from_hdr(hdr, sizeof(icmp_hdr), data_len, 0);
}


/*********************
 * ETHER HEADER DATA *
 *********************/


bool eth_hdr_data_is(ether_hdr *hdr, unsigned short type) {
    return hdr->ether_type == htons(type);
}

bool eth_hdr_data_is_ip(ether_hdr *hdr) {
    return eth_hdr_data_is(hdr, ETH_P_IP);
}

bool eth_hdr_data_is_arp(ether_hdr *hdr) {
    return eth_hdr_data_is(hdr, ETH_P_ARP);
}


/******************
 * IP HEADER DATA *
 ******************/


bool ip_hdr_data_is(ip_hdr *hdr, unsigned short proto) {
    return hdr->ip_proto == proto;
}

bool ip_hdr_data_is_tcp(ip_hdr *hdr) {
    return ip_hdr_data_is(hdr, IPPROTO_TCP);
}

bool ip_hdr_data_is_udp(ip_hdr *hdr) {
    return ip_hdr_data_is(hdr, IPPROTO_UDP);
}

bool ip_hdr_data_is_icmp(ip_hdr *hdr) {
    return ip_hdr_data_is(hdr, IPPROTO_ICMP);
}


/***********
 * HELPERS *
 ***********/



ether_hdr *get_current_ether_hdr() {
    return current_ether_hdr;
}

arp_hdr *get_current_arp_hdr() {
    unsigned char *h = get_current_ether_hdr();
    if (eth_hdr_data_is_arp((ether_hdr *) h)) {
        return (arp_hdr *) extract_data_from_eth_hdr(h, current_ether_hdr_len);
    } else {
        return NULL;
    }
}

ip_hdr *get_current_ip_hdr() {
    ether_hdr *h = get_current_ether_hdr();

    // If Ethernet header is not IP ignore
    if (eth_hdr_data_is_arp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if(current_network_data == NULL) {
        current_network_data = extract_data_from_eth_hdr((unsigned char *) h, current_ether_hdr_len);
    }

    return (ip_hdr*) current_network_data;
}

tcp_hdr *get_current_tcp_hdr() {
    ip_hdr *h = get_current_ip_hdr();

    // If Ethernet header is not ARP ignore
    if (ip_hdr_data_is_tcp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if(current_network_data == NULL) {
        current_network_data = extract_data_from_eth_hdr((unsigned char *) h, current_ether_hdr_len);
    }

    return (tcp_hdr*) current_network_data;
}

udp_hdr *get_current_udp_hdr() {
    ip_hdr *h = get_current_ip_hdr();

    // If Ethernet header is not ARP ignore
    if (ip_hdr_data_is_udp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if(current_network_data == NULL) {
        current_network_data = extract_data_from_eth_hdr((unsigned char *) h, current_ether_hdr_len);
    }

    return (udp_hdr*) current_network_data;
}

icmp_hdr *get_current_icmp_hdr() {
    ip_hdr *h = get_current_ip_hdr();

    // If Ethernet header is not ARP ignore
    if (ip_hdr_data_is_icmp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if(current_network_data == NULL) {
        current_network_data = extract_data_from_eth_hdr((unsigned char *) h, current_ether_hdr_len);
    }

    return (icmp_hdr*) current_network_data;
}

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

void run_not_filter() { stack[stackTop - 1] = (unsigned long) (stack[stackTop - 1] != 0); }

void run_eq_filter() {
//    printf("%lu == %lu ? ", stack[stackTop - 2], stack[stackTop - 1]);
    stack[stackTop - 2] = (unsigned long) (stack[stackTop - 2] == stack[stackTop - 1]);
//    printf("Result: %lu\n", stack[stackTop - 2]);
    stackTop--;
}

void run_and_filter() {
    stack[stackTop - 2] = (unsigned long) (stack[stackTop - 2] && stack[stackTop - 1]);
    stackTop--;
}

void run_or_filter() {
    stack[stackTop - 2] = (unsigned long) (stack[stackTop - 2] || stack[stackTop - 1]);
    stackTop--;
}

void run_ip_filter() {
    stack[stackTop++] = (unsigned long) (current_ether_hdr != NULL &&
                                         current_ether_hdr->ether_type == htons(ETH_P_IP));
}

void run_arp_filter() {
    stack[stackTop++] = (unsigned long) (current_ether_hdr != NULL &&
                                         current_ether_hdr->ether_type == htons(ETH_P_ARP));
}

void run_icmp_filter() {
    ip_hdr *h = get_current_ip_hdr();
    stack[stackTop++] = (unsigned long) (h != NULL && h->ip_proto == IPPROTO_ICMP);
}

void run_tcp_filter() {
    ip_hdr *h = get_current_ip_hdr();

    stack[stackTop++] = (unsigned long) (h != NULL && h->ip_proto == IPPROTO_TCP);
}

void run_udp_filter() {
    ip_hdr *h = get_current_ip_hdr();

    stack[stackTop++] = (unsigned long) (h != NULL && h->ip_proto == IPPROTO_UDP);
}


/*******************
 * PARSE FUNCTIONS *
 *******************/

unsigned char *parse_ether_addr(char *filter) {
    // 6 bytes used by an Ethernet Address
    unsigned char *ether = malloc(sizeof(unsigned char) * 6);

    // Copy string to use in strtok
    char *copy = malloc(sizeof(char) * (strlen(filter) + 1));
    strcpy(copy, filter);

    // Parse text value to byte
    ether[0] = (unsigned char) strtol(strtok(copy, ":"), NULL, 16);
    for (int j = 1; j < 6; ++j) {
        ether[j] = (unsigned char) strtol(strtok(NULL, ":"), NULL, 16);
    }

    return (unsigned char *) ether;
}

int parse_ip_addr(char *filter) {
    // Resulting int IP
    int result = 0;

    // Parsed IP segments
    int *ipp = malloc(sizeof(int) * 4);

    // 4 IP address segments
    char **ip = malloc(sizeof(char *) * 4);

    // Copy string to use in strtok
    char *copy = malloc(sizeof(char) * (strlen(filter) + 1));
    strcpy(copy, filter);

    // Split IP String
    ip[0] = strtok(copy, ".");
    for (int i = 1; i < 4; ++i) {
        ip[i] = strtok(NULL, ".");
    }

    // Parse to int
    for (int i = 0; i < 4; ++i) {
        ipp[i] = (int) strtol(ip[i], NULL, 10);
    }

    for (int i = 0; i < 4; ++i) {
        result += ipp[i] << ((3 - i) * 8);
    }

    // Return IP number array
    return result;
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

void push_ip_addr(const unsigned int ip) {
    stack[stackTop++] = ip & 0xFFFFFFFF;
}

void push_hex(unsigned int number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

void push_decimal(unsigned int number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

void push_ipproto() {
    ip_hdr *h = get_current_ip_hdr();

    if(h == NULL) {
        stack[stackTop++] = 0;
    } else{
        stack[stackTop++] = h->ip_proto;
    }
}

void push_ipfrom() {
    ip_hdr *h = get_current_ip_hdr();

    if (h != NULL) {
        push_ip_addr(ntohl(h->ip_src));
    } else {
        stack[stackTop++] = 0;
    }
}

void push_ipto() {
    ip_hdr *h = get_current_ip_hdr();

    if (h != NULL) {
        push_ip_addr(ntohl(h->ip_dst));
    } else {
        stack[stackTop++] = 0;
    }
}

void push_ethertype() {
    stack[stackTop++] = current_ether_hdr->ether_type;
}

void push_udptoport() {
    udp_hdr *h = get_current_udp_hdr();

    if (h != NULL) {
        stack[stackTop++] = h->dst_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

void push_udpfromport() {
    udp_hdr *h = get_current_udp_hdr();

    if (h != NULL) {
        stack[stackTop++] = h->src_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

void push_tcptoport() {
    tcp_hdr *h = get_current_tcp_hdr();

    if (h != NULL) {
        stack[stackTop++] = h->dst_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

void push_tcpfromport() {
    tcp_hdr *h = get_current_tcp_hdr();

    if (h != NULL) {
        stack[stackTop++] = h->src_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

void push_icmptype() {
    icmp_hdr *h = get_current_icmp_hdr();

    if (h != NULL) {
        stack[stackTop++] = h->type;
    } else {
        stack[stackTop++] = 0;
        return;
    }
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

void set_ether_header(ether_hdr *ether_hdr, long len) {
    current_ether_hdr = ether_hdr;
    current_ether_hdr_len = len;
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
    current_network_data = NULL;
    current_transport_data = NULL;

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
    char *str = malloc(sizeof(char) * 18); // 17 characters + null-terminator

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

char *ip_addr_to_string(unsigned int ip) {
    short parts[4];
    unsigned int mask = 0xFF;
    for (int i = 0; i < 4; ++i) {
        parts[3 - i] = (unsigned short) ((ip >> i * 8) & mask);
    }

    char *str_ip = malloc(sizeof(char) * 16); // 3*4 numbers + 3 dots + 1 \0

    sprintf(str_ip, "%000d.%000d.%000d.%000d", parts[0], parts[1], parts[2], parts[3]);

    return str_ip;
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

char *get_proto_name(int proto) {
    struct protoent *a = getprotobynumber(proto);
    if(a != NULL) {
        return a->p_name;
    } else {
        return "?";
    }
}

char *get_make_from_ether_addr(unsigned int *addr) {
    return "Intel";
}

bool eth_is_broadcast(ether_hdr *eth) {
    for (int i = 0; i < 6; ++i) {
        if(eth->ether_dhost[i] != 0xFF) {
            return false;
        }
    }

    return true;
}

void print_ip_hdr(ip_hdr *hdr, int data_size) {

    printf("IP: ----- IP Header -----\n"
           "IP:\n"
           "IP: Version             = %d\n"
           "IP: Header length       = %d bytes\n"
           "IP: Type of service     = %d\n"
           "IP: ..0. .... routine\n"
           "IP: ...0 .... normal delay\n"
           "IP: .... 0... normal throughput\n"
           "IP: .... .0.. normal reliability\n"
           "IP: Total length        = %d bytes\n"
           "IP: Identification      = %d\n"
           "IP: Flags               = %01x\n"
           "IP: .%d.. .... may fragment\n"
           "IP: ..%d. .... more fragments\n"
           "IP: Fragment offset     = %d bytes\n"
           "IP: Time to live        = %d seconds/hops\n"
           "IP: Protocol            = %d (%s)\n"
           "IP: Header checksum     = %X\n"
           "IP: Source address      = %s,\n"
           "IP: Destination address = %s,\n"
           "IP:\n",
           hdr->ip_v,
           ntohs(hdr->ip_len),
           hdr->ip_tos,
           data_size - (int) sizeof(ip_hdr),
           ntohs(hdr->ip_id),
           hdr->ip_flags & 0x4,
           (hdr->ip_flags & 0x1) == (0x1),
           (hdr->ip_flags & 0x2) == (0x2),
           ntohs(hdr->ip_offset),
           hdr->ip_ttl,
           hdr->ip_proto, get_proto_name(hdr->ip_proto),
           ntohs(hdr->ip_csum),
           ip_addr_to_string(ntohl(hdr->ip_src)),
           ip_addr_to_string(ntohl(hdr->ip_dst))
    );
}

void print_ether_hdr(ether_hdr *hdr, int data_size) {

    int order = packet_count;
    int size = data_size;
    int type_number = ntohs(hdr->ether_type);
    char *type_name = get_ether_type_name(ntohs(hdr->ether_type));
    char *dst_addr = ether_addr_to_string(hdr->ether_dhost);
    char *src_addr = ether_addr_to_string(hdr->ether_shost);
    char *make = get_make_from_ether_addr(hdr->ether_shost);
    char  *broadcast = (eth_is_broadcast(hdr)) ? ", (broadcast)" : "";

    printf("ETHER:  ----- Ethernet Header -----\n"
           "ETHER:\n"
           "ETHER:  Packet %d\n"
           "ETHER:  Packet size = %d bytes\n"
           "ETHER:  Destination = %s%s\n"
           "ETHER:  Source      = %s, %s\n"
           "ETHER:  Ethertype   = %x (%s)\n"
           "ETHER:\n",
            /* Packet      */ order,
            /* Packet size */ size,
            /* Destination */ dst_addr, broadcast,
            /* Source      */ src_addr, make,
            /* Ethertype   */ type_number, type_name
    );

    if(get_current_ip_hdr() != NULL) {
        print_ip_hdr(get_current_ip_hdr(), current_ether_hdr_len - sizeof(ether_hdr));
    }
}


// Break this function to implement the functionalities of your packet analyser
void process(unsigned char *packet, long len) {
    // Check if frame is valid
    if (len == 0)
        return;

    // Cast packet data to Ethernet Header struct
    ether_hdr *eth = (ether_hdr *) packet;

    // Extract header data
    unsigned char *data = extract_data_from_hdr((unsigned char *) eth, sizeof(ether_hdr), len, 0);

    // Globally set current Ethernet header to be used to run filters
    set_ether_header(eth, len);

    // Check if packet should be filtered
    if (!is_filtered()) {
        accepted_packets++;
        sequential_rejected_packets = 0;

        printf("\r");
        print_ether_hdr(current_ether_hdr, len);

    } else {
        printf("\rPackets rejected in a row: %d", ++sequential_rejected_packets);
    }

    fflush(stdout);
}

void signal_handler(int signal) {
    printf("\n"
           "ethernet frames:       %d\n"
           "ethernet broadcast:    %d\n"
           "ARP                    %d\n"
           "IP                     %d\n"
           "ICMP                   %d\n"
           "UDP                    %d\n"
           "TCP                    %d\n"
           "To this host:          %d\n",
           0,0,0,0,0,0,0,0);

    // Continue signal propagation
    exit(signal);
}

void register_signal_handler() {
    signal(SIGTERM, signal_handler);
}

int main(int argc, char **argv) {
    long n;
    int sockfd;
    unsigned char *packet_buffer;
    stack = malloc(sizeof(long) * MAX_FILTER_STACK);

    // Read parameters and filters
    process_parameters(argc, argv);
    register_signal_handler();

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
        process(packet_buffer, n);
    }

    free(packet_buffer);
    close(sockfd);
    printf("Ended\n");
    return 0;
}
