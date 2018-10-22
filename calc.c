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
} eth_hdr;

typedef struct _ip_hdr {
    unsigned char version:4;        // IP Version
    unsigned char length:4;    // Header length
    unsigned char type_of_service;        // Type of service
    unsigned short total_length;        // Datagram Length
    unsigned short identification;        // Datagram identifier
    unsigned short flags:3;
    unsigned short offset:13;    // Fragment offset
    unsigned char time_to_live;        // Time To Live
    unsigned char proto;    // Protocol
    unsigned short checksum;    // Header checksum
    unsigned int source;        // Source IP address
    unsigned int destination;        // Destination IP address
} ip_hdr;

typedef struct _arp_hdr {
    unsigned short hardware_type;
    unsigned short protocol_type;
    unsigned char hardware_length;
    unsigned char protocol_length;
    unsigned short opcode;
    unsigned char sender_mac[6];
    unsigned int sender_ip;
    unsigned char destination_mac[6];
    unsigned int destination_ip;
} arp_hdr;

typedef struct _udp_hdr {
    unsigned short source_port;
    unsigned short destination_port;
    unsigned short length;
    unsigned short checksum;
} udp_hdr;

typedef struct _tcp_hdr {
    unsigned short source_port;
    unsigned short destination_port;
    unsigned int sequence_number;
    unsigned int ack_number;
    unsigned char offset:4;
    unsigned short flags:12;
    unsigned short window_size;
    unsigned short checksum;
    unsigned short urgent_pointer;
} tcp_hdr;

typedef struct _icmp_hdr {
    unsigned char type;
    unsigned char code;
    unsigned short checksum;
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

// Stats
int udp_packets = 0;
int tcp_packets = 0;
int icmp_packets = 0;
int ip_packets = 0;
int arp_packets = 0;
int eth_frames = 0;
int eth_broadcasts = 0;

// Accept packets
int accepted_packets = 0;

// How many packets were rejected in a row
int sequential_rejected_packets = 0;

// Filter stack
unsigned long *stack;

// Where is the top of the stack
int stackTop = 0;

// List of filters
char **filters;

// Current headers to be filtered
eth_hdr *current_eth_hdr = NULL;
long current_eth_hdr_len = 0;

// Caches to avoid helper functions re-calculating stuff
unsigned char *current_network_data = NULL;  // ARP/IP
unsigned char *current_transport_data = NULL; // TCP/UDP


/******************
 * MISC FUNCTIONS *
 ******************/


/**
 * Check if string 'a' == 'b'
 *
 * @param a - string a
 * @param b - string b
 *
 * @return - is 'a' == 'b'
 */
bool streq(char *a, char *b) {
    return strcmp(a, b) == 0;
}

bool is_little_endian() {
    return (*(char *) (int[]) {1});
}

void fix_little_endian_ip_hdr(ip_hdr *hdr) {
    if (is_little_endian()) {
        // Flip version and length
        unsigned char t = hdr->version;
        hdr->version = hdr->length;
        hdr->length = t;


        unsigned long tmp = (unsigned long) hdr->flags + ((unsigned long) hdr->offset << 3);
        hdr->flags = (unsigned short) (tmp & 0x1C00); // extract most sig 3 bits
        hdr->offset = (unsigned short) (tmp & 0xFFFF); // extract least sig 2 bytes
    }
}

void fix_little_endian_tcp_hdr(tcp_hdr *hdr) {
    if (is_little_endian()) {
        unsigned short tmp = hdr->offset;
        hdr->offset = (unsigned char) (hdr->flags & 0xF);

        unsigned short a = (unsigned short) (tmp & 0xF);
        unsigned short b = (unsigned short) (hdr->flags & 0xFF);
        hdr->flags = (a << 8) | b;
        // hdr->flags = ((unsigned short) (tmp << 4)) + ((unsigned short) ((hdr->flags & 0xF) >> 4)) + ((unsigned short) ((hdr->flags & 0xF0) << 4));
    }
}


/**************************
 * HEADER DATA EXTRACTORS *
 **************************/

/**
 * Extracts data from generic header
 *
 * @param hdr - header data
 * @param hdr_size - header initial information
 * @param size - entire packet size
 * @param hdr_tail - size o3252f tail information (checksum, etc)
 *
 * @return - bytes from header data
 */
unsigned char *extract_data_from_hdr(unsigned char *hdr, unsigned int hdr_size, long size, unsigned int hdr_tail) {
    unsigned int udp_data_len = ((unsigned int) size) - hdr_size - hdr_tail;
    unsigned char *udp_data = malloc(sizeof(unsigned char) * (udp_data_len - hdr_tail));

    memcpy(udp_data, hdr + hdr_size, udp_data_len);

    return udp_data;
}

/**
 * Extracts data from Ethernet frame
 *
 * @param hdr - frame data
 * @param size - frame size
 *
 * @return - bytes from frame data
 */
unsigned char *extract_data_from_eth_hdr(unsigned char *hdr, long size) {
    return extract_data_from_hdr(hdr, sizeof(eth_hdr), size, 0);
}

/**
 * Extracts data from ARP header
 *
 * @param hdr - header data
 * @param size - header size
 *
 * @return - bytes from header data
 */
unsigned char *extract_data_from_arp_hdr(unsigned char *hdr, long size) {
    return extract_data_from_hdr(hdr, sizeof(arp_hdr), size, 0);
}

/**
 * Extracts data from IP header
 *
 * @param hdr - header data
 * @param size - header size
 *
 * @return - bytes from header data
 */
unsigned char *extract_data_from_ip_hdr(unsigned char *hdr, long size) {
    return extract_data_from_hdr(hdr, sizeof(ip_hdr), size, 0);
}

/**
 * Extracts data from TCP header
 *
 * @param hdr - header data
 * @param size - header size
 *
 * @return - bytes from header data
 */
unsigned char *extract_data_from_tcp_hdr(unsigned char *hdr, long size) {
    return extract_data_from_hdr(hdr, sizeof(tcp_hdr), size, 0);
}

/**
 * Extracts data from UDP header
 *
 * @param hdr - header data
 * @param size - header size
 *
 * @return - bytes from header data
 */
unsigned char *extract_data_from_udp_hdr(unsigned char *hdr, long size) {
    return extract_data_from_hdr(hdr, sizeof(udp_hdr), size, 0);
}

/**
 * Extracts data from ICMP header
 *
 * @param hdr - header data
 * @param size - header size
 *
 * @return - bytes from header data
 */
unsigned char *extract_data_from_icmp_hdr(unsigned char *hdr, long size) {
    return extract_data_from_hdr(hdr, sizeof(icmp_hdr), size, 0);
}


/************************
 * ETHERNET HEADER DATA *
 ************************/


/**
 * Checks what protocol is inside Ethernet frame
 *
 * @param hdr - header data
 * @param proto - protocol to compare
 *
 * @return - is header contains 'proto'
 */
bool eth_hdr_data_is(eth_hdr *hdr, unsigned short proto) {
    return hdr->ether_type == htons(proto);
}

/**
 * Check if header data is IP Packet
 *
 * @param hdr - header data
 *
 * @return - if 'hdr' contains IP protocol
 */
bool eth_hdr_data_is_ip(eth_hdr *hdr) {
    return eth_hdr_data_is(hdr, ETH_P_IP);
}

/**
 * Check if header data is ARP Packet
 *
 * @param hdr - header data
 *
 * @return - if 'hdr' contains ARP protocol
 */
bool eth_hdr_data_is_arp(eth_hdr *hdr) {
    return eth_hdr_data_is(hdr, ETH_P_ARP);
}


/******************
 * IP HEADER DATA *
 ******************/


/**
 * Check what protocol is inside IP Packet
 *
 * @param hdr - header data
 * @param proto - protocol to compare
 *
 * @return - if header data is 'proto'
 */
bool ip_hdr_data_is(ip_hdr *hdr, unsigned short proto) {
    return hdr->proto == proto;
}

/**
 * Check if IP Packet contains TCP Packet
 *
 * @param hdr - header data
 *
 * @return - if header data is TCP
 */
bool ip_hdr_data_is_tcp(ip_hdr *hdr) {
    return ip_hdr_data_is(hdr, IPPROTO_TCP);
}

/**
 * Check if IP Packet contains UDP Packet
 *
 * @param hdr - header data
 *
 * @return - if header data is UDP
 */
bool ip_hdr_data_is_udp(ip_hdr *hdr) {
    return ip_hdr_data_is(hdr, IPPROTO_UDP);
}

/**
 * Check if IP Packet contains ICMP Packet
 *
 * @param hdr - header data
 *
 * @return - if header data is ICMP
 */
bool ip_hdr_data_is_icmp(ip_hdr *hdr) {
    return ip_hdr_data_is(hdr, IPPROTO_ICMP);
}


/***********
 * HELPERS *
 ***********/


/**
 * Get current Ethernet frame being processed
 *
 * @return - current Ethernet frame
 */
eth_hdr *get_current_eth_hdr() {
    return current_eth_hdr;
}

/**
 * Tries to extract an ARP header from current Ethernet frame
 *
 * @return - ARP header if it exists
 */
arp_hdr *get_current_arp_hdr() {
    eth_hdr *h = get_current_eth_hdr();

    if(h == NULL) {
        return NULL;
    }

    // Check if current frame is ARP
    if ( eth_hdr_data_is_arp((eth_hdr *) h)) {
        return ((arp_hdr *) extract_data_from_eth_hdr((unsigned char *) h, current_eth_hdr_len));
    } else {
        return NULL;
    }
}

/**
 * Tries to extract an IP header from current Ethernet frame
 *
 * @return - IP header if it exists
 */
ip_hdr *get_current_ip_hdr() {
    eth_hdr *h = get_current_eth_hdr();

    if(h == NULL) {
        return NULL;
    }

    // If Ethernet header is not IP ignore
    if (!eth_hdr_data_is_ip(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if (current_network_data == NULL) {
        current_network_data = extract_data_from_eth_hdr((unsigned char *) h, current_eth_hdr_len);
        fix_little_endian_ip_hdr((ip_hdr *) current_network_data);
    }


    return (ip_hdr *) current_network_data;
}

/**
 * Tries to extract an TCP header from current IP Packet (if current frame is for IP protocol)
 *
 * @return - TCP header if it exists
 */
tcp_hdr *get_current_tcp_hdr() {
    ip_hdr *h = get_current_ip_hdr();

    if(h == NULL) {
        return NULL;
    }

    // If Ethernet header is not ARP ignore
    if (!ip_hdr_data_is_tcp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if (current_transport_data == NULL) {
        current_transport_data = extract_data_from_eth_hdr((unsigned char *) h, current_eth_hdr_len);
        fix_little_endian_tcp_hdr((tcp_hdr *) current_transport_data);
    }

    return (tcp_hdr *) current_transport_data;
}

/**
 * Tries to extract an UDP  header from current IP Packet (if current frame is for IP protocol)
 *
 * @return - UDP header if it exists
 */
udp_hdr *get_current_udp_hdr() {
    ip_hdr *h = get_current_ip_hdr();

    if(h == NULL) {
        return NULL;
    }

    // If Ethernet header is not ARP ignore
    if (!ip_hdr_data_is_udp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if (current_transport_data == NULL) {
        current_transport_data = extract_data_from_eth_hdr((unsigned char *) h, current_eth_hdr_len);
    }

    return (udp_hdr *) current_transport_data;
}

/**
 * Tries to extract an ICMP header from current IP Packet (if current frame is for IP protocol)
 *
 * @return - ICMP header if it exists
 */
icmp_hdr *get_current_icmp_hdr() {
    ip_hdr *h = get_current_ip_hdr();

    if(h == NULL) {
        return NULL;
    }

    // If Ethernet header is not ARP ignore
    if (!ip_hdr_data_is_icmp(h)) {
        return NULL;
    }

    // Check if extraction is needed
    if (current_transport_data == NULL) {
        current_transport_data = extract_data_from_eth_hdr((unsigned char *) h, current_eth_hdr_len);
    }

    return (icmp_hdr *) current_transport_data;
}


/***********
 * FILTERS *
 ***********/


/**
 * Runs MOD (%) filter on stack
 */
void run_mod_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] % stack[stackTop - 1]);
    stackTop--;
}

/**
 * Runs DIVISION filter on stack
 */
void run_div_filter() {
    if (stack[stackTop - 1] == 0) {
        stack[stackTop - 2] = (stack[stackTop - 2] / stack[stackTop - 1]);
    } else {
        stack[stackTop - 2] = 0;
    }
    stackTop--;
}

/**
 * Runs MULTIPLICATION filter on stack
 */
void run_mult_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] * stack[stackTop - 1]);
    stackTop--;
}

/**
 * Runs SUBTRACTION filter on stack
 */
void run_minus_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] - stack[stackTop - 1]);
    stackTop--;
}

/**
 * Runs PLUS filter on stack
 */
void run_plus_filter() {
    stack[stackTop - 2] = (stack[stackTop - 2] + stack[stackTop - 1]);
    stackTop--;
}

/**
 * Runs NOT filter on stack
 */
void run_not_filter() {
    stack[stackTop - 1] = (unsigned long) (stack[stackTop - 1] != 0);
}

/**
 * Runs EQUALS filter on stack
 */
void run_eq_filter() {
//    printf("%lu == %lu ? ", stack[stackTop - 2], stack[stackTop - 1]);
    stack[stackTop - 2] = (unsigned long) (stack[stackTop - 2] == stack[stackTop - 1]);
//    printf("Result: %lu\n", stack[stackTop - 2]);
    stackTop--;
}

/**
 * Runs AND filter on stack
 */
void run_and_filter() {
    stack[stackTop - 2] = (unsigned long) (stack[stackTop - 2] && stack[stackTop - 1]);
    stackTop--;
}

/**
 * Runs OR filter on stack
 */
void run_or_filter() {
    stack[stackTop - 2] = (unsigned long) (stack[stackTop - 2] || stack[stackTop - 1]);
    stackTop--;
}

/**
 * Runs IP filter on stack (stack 1 if current frame is IP)
 */
void run_ip_filter() {
    stack[stackTop++] = (unsigned long) (current_eth_hdr != NULL &&
                                         current_eth_hdr->ether_type == htons(ETH_P_IP));
}

/**
 * Runs ARP filter on stack (stack 1 if current frame is ARP)
 */
void run_arp_filter() {
    stack[stackTop++] = (unsigned long) (current_eth_hdr != NULL &&
                                         current_eth_hdr->ether_type == htons(ETH_P_ARP));
}

/**
 * Runs ICMP filter on stack (stack 1 if current packet is ICMP)
 */
void run_icmp_filter() {
    ip_hdr *h = get_current_ip_hdr();

    if(h != NULL) {
        stack[stackTop++] = (unsigned long) (h != NULL && h->proto == IPPROTO_ICMP);
    } else {
        stack[stackTop++] = 0;
    }
}

/**
 * Runs TCP filter on stack (stack 1 if current packet is TCP)
 */
void run_tcp_filter() {
    ip_hdr *h = get_current_ip_hdr();

    if(h != NULL) {
        stack[stackTop++] = (unsigned long) (h != NULL && h->proto == IPPROTO_TCP);
    } else {
        stack[stackTop++] = 0;
    }
}

/**
 * Runs UDP filter on stack (stack 1 if current packet is UDP)
 */
void run_udp_filter() {
    ip_hdr *h = get_current_ip_hdr();

    if(h != NULL) {
        stack[stackTop++] = (unsigned long) (h != NULL && h->proto == IPPROTO_UDP);
    } else {
        stack[stackTop++] = 0;
    }
}


/*******************
 * PARSE FUNCTIONS *
 *******************/


/**
 * Parses Ethernet address to 6 bytes
 *
 * @param addr - ethernet address in string form
 *
 * @return - ethernet address in byte form
 */
unsigned char *parse_eth_addr(char *addr) {
    // 6 bytes used by an Ethernet Address
    unsigned char *ether = malloc(sizeof(unsigned char) * 6);

    // Copy string to use in strtok
    char *copy = malloc(sizeof(char) * (strlen(addr) + 1));
    strcpy(copy, addr);

    // Parse text value to byte
    ether[0] = (unsigned char) strtol(strtok(copy, ":"), NULL, 16);
    for (int j = 1; j < 6; ++j) {
        ether[j] = (unsigned char) strtol(strtok(NULL, ":"), NULL, 16);
    }

    return ether;
}

/**
 * Parses IP address to int form
 *
 * @param filter - ip address in string form
 *
 * @return - ip address in int form
 */
unsigned int parse_ip_addr(char *filter) {
    // Resulting int IP
    int unsigned result = 0;

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

/**
 * Parses decimal number in string form
 *
 * @param number - decimal number in string form
 *
 * @return - decimal number as long
 */
unsigned long parse_decimal(char *number) {
    long int i = strtol(number, NULL, 10);

    return (unsigned long) i;
}

/**
 * Parses hexadecimal number in string form
 *
 * @param number - hexadecimal number in string form
 *
 * @return - number as long
 */
unsigned long parse_hex(char *number) {
    long int i = strtol(number, NULL, 16);

    return (unsigned long) i;
}


/******************
 * PUSH FUNCTIONS *
 ******************/


/**
 * Pushes Ethernet address to stack
 *
 * @param ether - ethernet address in byte form
 */
void push_ether_addr(const unsigned char ether[6]) {
    unsigned long i = 0;

    // Convert Ethernet address to numeric form
    for (int j = 0; j < 6; ++j) {
        i += (ether[j]) << 8 * (5 - j);
    }

    // Mask last 6 bytes
    stack[stackTop++] = i & 0xFFFFFFFFFFFF;
}

/**
 * Pushes IP address to stack
 *
 * @param ip - ip address in numeric form
 */
void push_ip_addr(const unsigned int ip) {
    // Mask last 4 bytes
    stack[stackTop++] = ip & 0xFFFFFFFF;
}

/**
 * Pushes HEX to stack (this is the same thing as push_decimal, with different name in case mask changes)
 *
 * @param number - hex in digit
 */
void push_hex(unsigned long number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

/**
 * Push DECIMAL to stack
 *
 * @param number - hex in digit
 */
void push_decimal(unsigned long number) {
    stack[stackTop++] = number & 0xFFFFFFFF;
}

/**
 * Push IP Protocol to stack (if current packet is IP)
 */
void push_ipproto() {
    ip_hdr *h = get_current_ip_hdr();

    // Stack 0 if current header is not IP
    if (h == NULL) {
        stack[stackTop++] = 0;
    } else {
        stack[stackTop++] = h->proto;
    }
}

/**
 * Push IP address source to stack (if current packet is IP)
 */
void push_ipfrom() {
    ip_hdr *h = get_current_ip_hdr();

    // Stack 0 if current header is not IP
    if (h != NULL) {
        push_ip_addr(ntohl(h->source));
    } else {
        stack[stackTop++] = 0;
    }
}

/**
 * Push IP address destination to stack (if current packet is IP)
 */
void push_ipto() {
    ip_hdr *h = get_current_ip_hdr();

    // Stack 0 if current header is not IP
    if (h != NULL) {
        push_ip_addr(ntohl(h->destination));
    } else {
        stack[stackTop++] = 0;
    }
}

/**
 * Push Ethernet type to stack
 */
void push_ethertype() {
    stack[stackTop++] = current_eth_hdr->ether_type;
}

/**
 * Push UDP destination port
 */
void push_udptoport() {
    udp_hdr *h = get_current_udp_hdr();

    // Stack 0 if current header is not IP and UDP
    if (h != NULL) {
        stack[stackTop++] = h->destination_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

/**
 * Push UDP source port
 */
void push_udpfromport() {
    udp_hdr *h = get_current_udp_hdr();

    // Stack 0 if current header is not IP and UDP
    if (h != NULL) {
        stack[stackTop++] = h->source_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}


/**
 * Push TCP destination port
 */
void push_tcptoport() {
    tcp_hdr *h = get_current_tcp_hdr();

    // Stack 0 if current header is not IP and TCP
    if (h != NULL) {
        stack[stackTop++] = h->destination_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

/**
 * Push TCP source port
 */
void push_tcpfromport() {
    tcp_hdr *h = get_current_tcp_hdr();

    // Stack 0 if current header is not IP or TCP
    if (h != NULL) {
        stack[stackTop++] = h->source_port;
    } else {
        stack[stackTop++] = 0;
        return;
    }
}

/**
 * Push ICMP type
 */
void push_icmptype() {
    icmp_hdr *h = get_current_icmp_hdr();

    // Stack 0 if current header is not IP or ICMP
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


/**
 * Checks if string is a decimal number
 *
 * @param c - string to check
 *
 * @return - if string is a decimal
 */
bool is_decimal(char *c) {
    int index = 0;
    int size = (int) strlen(c);

    // Check if every index of string is a digit
    while (isdigit(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

/**
 * Checks if string is a hex number
 *
 * @param c - string to check
 *
 * @return - if string is a hex number
 */
bool is_hex(char *c) {
    int index = 0;
    int size = (int) strlen(c);

    // Check hex prefix
    if (c[index] == '0' && index < size) {
        index++;
    }
    if (c[index] == 'x' && index < size) {
        index++;
    }

    // Check if remaining string is alphanumeric
    while (isalnum(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

/**
 * Check if string is an IP address
 *
 * @param c - string to check
 *
 * @return - if string is an IP address
 */
bool is_ip_addr(char *c) {
    int index = 0;
    int size = (int) strlen(c);

    // Check 3 times for 3 numbers and a dot
    for (int i = 0; i < 3; ++i) {
        while (isdigit(c[index]) && index < size) {
            index++;
        }
        if (c[index] == '.' && index < size) {
            index++;
        }
    }

    // Check for last segment of IP address
    while (isdigit(c[index]) && index < size) {
        index++;
    }

    return index == size;
}

/**
 * Check if string is an Ethernet address
 *
 * @param c - string to check
 *
 * @return - if string is Ethernet address
 */
bool is_eth_addr(char *c) {
    int index = 0;
    int size = (int) strlen(c);

    // Check 5 times for numbers and semicolon
    for (int i = 0; i < 5; ++i) {
        while (isalnum(c[index]) && index < size) {
            index++;
        }
        if (c[index] == ':' && index < size) {
            index++;
        }
    }

    // Check if last segment of Ethernet address exists
    while (isalnum(c[index]) && index < size) {
        index++;
    }

    return index == size;
}


/***************************
 *  FILTER SETUP FUNCTIONS *
 ***************************/

/**
 * Sets current global frame
 *
 * @param eth_hdr - new ethernet frame
 * @param len - size of frame
 */
void set_eth_header(eth_hdr *eth_hdr, long len) {
    current_eth_hdr = eth_hdr;
    current_eth_hdr_len = len;
}

/**
 * Print the expected command line for the program
 */
void print_usage() {
    printf("xnoop -i <interface> [options] [filter]\n");
    exit(1);
}

/**
 * Process a single argument
 *
 * @param argi - argument index
 * @param argv - argument list
 *
 * @return - how many arguments were used (1 for flags, 2 for parameters)
 */
int process_argument(int argi, char **argv) {
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

/**
 * Process program arguments
 *
 * @param argc - argument count
 * @param argv - argument array
 */
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
        used = process_argument(index, argv);
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

/**
 * Resets any stack information for next packet
 */
void reset_stack() {
    // Reset stack top and packet data cache
    stackTop = 0;
    current_network_data = NULL;
    current_transport_data = NULL;

    // Debugging use only
    for (int i = 0; i < MAX_FILTER_STACK; ++i) {
        stack[i] = 0;
    }
}

/**
 * Runs a single filter in current stack
 *
 * @param filter - filter name
 */
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
        push_ether_addr(current_eth_hdr->ether_dhost);
    } else if (streq("etherfrom", filter)) {
        push_ether_addr(current_eth_hdr->ether_shost);
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
    } else if (is_eth_addr(filter)) {
        push_ether_addr(parse_eth_addr(filter));
    } else {
        printf("Could not find filter: %s\n", filter);
        exit(1);
    }
}

/**
 * Runs every filter passed as program argument
 */
void run_filters() {
    // Run each filter in order
    for (int i = 0; i < filter_count; ++i) {
//        printf("Running filter: %s\n", filters[i]);
        run_filter(filters[i]);
    }

    // Check if no filter is present (if so, modify stack to avoid filtering)
    if (filter_count == 0) {
        stack[0] = 1;
    }
}

/**
 * Bind a socket to a interface
 *
 * @param fd - socket file descriptor
 * @param iface_name - interface name
 *
 * @return - operation result code
 */
int bind_iface_name(int fd, char *iface_name) {
    return setsockopt(fd, SOL_SOCKET, SO_BINDTODEVICE, iface_name, (socklen_t) strlen(iface_name));
}

/**
 * Check if current packet is being filtered
 *
 * @return - if it's filtered
 */
bool is_filtered() {
    reset_stack();
    run_filters();

    return stack[0] == 0;
}

/**
 * Builds Ethernet address to string
 *
 * @param addr - ethernet address in byte form
 *
 * @return - ethernet address in string form
 */
char *eth_addr_to_string(unsigned char *addr) {
    char *str = malloc(sizeof(char) * 18); // 17 characters + null-terminator

    // Format address to string
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

/**
 * Builds IP address to string
 *
 * @param ip - ip address in numeric form
 *
 * @return - ip address in string form
 */
char *ip_addr_to_string(unsigned int ip) {
    short parts[4];
    unsigned int mask = 0xFF;

    // Mask each segment of IP address
    for (int i = 0; i < 4; ++i) {
        parts[3 - i] = (unsigned short) ((ip >> i * 8) & mask);
    }

    // Allocate resulting string
    char *str_ip = malloc(sizeof(char) * 16); // 3*4 numbers + 3 dots + 1 \0

    // Print to string form
    sprintf(str_ip, "%000d.%000d.%000d.%000d", parts[0], parts[1], parts[2], parts[3]);

    return str_ip;
}

/**
 * Get Ethernet protocol name by its ID
 *
 * @param type - protocol id
 *
 * @return - protocol name
 */
char *get_eth_type_name(unsigned int type) {
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

/**
 * Returns the name of the OPCode
 *
 * @param opcode - ARP OPCode
 *
 * @return - OPCode name
 */
char *get_arp_opcode_string(unsigned int opcode) {
    switch (opcode) {
        case 1:
            return "REQUEST";
        case 2:
            return "REPLY";
        default:
            return "?";
    }
}

/**
 * Return ICMP type description
 *
 * @param type - type number
 *
 * @return type description
 */
char *get_icmp_type_string(unsigned int type) {
    switch (type) {
        case 0:
            return "Echo Reply";
        case 3:
            return "Destination Unreachable";
        case 4:
            return "Source Quench (Deprecated)";
        case 5:
            return "Redirect";
        case 6:
            return "Alternate Host Address (Deprecated)";
        case 8:
            return "Echo";
        default:
            return "?";
    }
}


/**
 * Get IP protocol name by its ID
 *
 * @param proto - ip protocol id
 *
 * @return - ip protocol name
 */
char *get_ip_proto_name(int proto) {
    struct protoent *a = getprotobynumber(proto);

    // If 'protoent' exists, return the name
    if (a != NULL) {
        return a->p_name;
    } else {
        return "?";
    }
}

/**
 * Returns well known ports protocol name
 *
 * @param port - port number
 *
 * @return - protocol name
 */

char *get_known_port_name(int port) {
    // TODO: correctly add list of ports
    switch (port) {
        case 22:
            return "SSH";
        case 21:
            return "FTP";
        case 80:
            return "HTTP";
        default:
            return "Unknown";
    }
}

/**
 * Get make name from Ethernet address
 *
 * @param addr - ethernet address
 *
 * @return - make name
 */
char *get_make_from_ether_addr(unsigned char *addr) {
    return "Intel";
}

/**
 * Check if Ethernet address is FF:FF:FF:FF:FF:FF
 *
 * @param eth - ethernet address
 *
 * @return - if ethernet address is broadcast
 */
bool eth_is_broadcast(eth_hdr *eth) {
    // Check each segment for 0xFF
    for (int i = 0; i < 6; ++i) {
        if (eth->ether_dhost[i] != 0xFF) {
            return false;
        }
    }

    return true;
}

/**
 * Printers one only of bytes
 *
 * @param data - data pointer
 * @param size - data length
 * @param pad  - width target to pad
 */
void print_byte_data(unsigned char *data, unsigned long size, unsigned long pad) {
    for (int i = 0; i < pad; ++i) {
        if(i < size) {
            printf("%02x", data[i]);
        } else {
            printf("  ");
        }
        if (i % 2 == 1 && i > 0) printf(" ");
    }
    printf("\"");
    for (int i = 0; i < size; ++i) {
        printf("%c", data[i]);
    }
    printf("\"");
}

/**
 * Prints a X bytes in lines of 16 bytes
 *
 * @param data - pointer to data
 * @param data_size - data length
 * @param prefix - printer line prefix
 */
void print_byte_block(unsigned char *data, long data_size, char* prefix) {
    // For 64 bytes
    for (int i = 0; i < 64; i += 16) {
        // Check distance from end of data
        long len = data_size - i;

        // Stop if already over end
        if(len < 0) {
            break;
        }

        // If we have more than 16 bytes, clamp line to 16 bytes
        if(len > 16) {
            len = 16;
        }

        // Start printing data line
        printf("%s", prefix);
        print_byte_data(data + i, (unsigned long) len, 16);
        printf("\n");
    }
    printf("UDP: ");
}

void print_udp_hdr(udp_hdr *hdr, long data_size) {
    udp_packets++;
    printf("UDP:  ----- UDP Header -----\n"
           "UDP:\n"
           "UDP:  Source port = %d\n"
           "UDP:  Destination port = %d\n"
           "UDP:  Length = %d\n"
           "UDP:  Checksum = 0x%x\n"
           "UDP:\n"
           "UDP: Data: First 64 bytes\n",
           /* source port      */ ntohs(hdr->source_port),
           /* destination port */ ntohs(hdr->destination_port),
           /* length           */ ntohs(hdr->length),
           /* checksum         */ ntohs(hdr->checksum)
    );

    print_byte_block(extract_data_from_udp_hdr((unsigned char*) hdr, data_size), data_size, "UDP: ");
}

/**
 * Pretty print TCP header
 *
 * @param hdr - header data
 * @param data_size - header size
 */
void print_tcp_hdr(tcp_hdr *hdr, long data_size) {
    tcp_packets++;
    printf("TCP:  ----- TCP Header -----\n"
           "TCP:\n"
           "TCP:  Source port = %d\n"
           "TCP:  Destination port = %d (%s)\n"
           "TCP:  Sequence number = %d\n"
           "TCP:  Acknowledgement number = %d\n"
           "TCP:  Data offset = %d bytes\n"
           "TCP:  Flags = 0x%x\n"
           "TCP:        ..%d. .... = Urgent pointer\n"
           "TCP:        ...%d .... = Acknowledgement\n"
           "TCP:        .... %d... = Push\n"
           "TCP:        .... .%d.. = Reset\n"
           "TCP:        .... ..%d. = Syn\n"
           "TCP:        .... ...%d = Fin\n"
           "TCP:  Window = %d\n"
           "TCP:  Checksum = 0x%x\n"
           "TCP:  Urgent pointer = %d\n"
           "TCP: Data: (first 64 bytes)\n",
           /* source port      */ ntohs(hdr->source_port),
           /* destination port */ ntohs(hdr->destination_port), get_known_port_name(ntohs(hdr->destination_port)),
           /* sequence number  */ ntohl(hdr->sequence_number),
           /* ack number       */ ntohl(hdr->ack_number),
           /* offset           */ hdr->offset,
           /* flags            */ hdr->flags,
           /* flag 1           */ ((hdr->flags >> 5) & 1) == 1,
           /* flag 2           */ ((hdr->flags >> 4) & 1) == 1,
           /* flag 3           */ ((hdr->flags >> 3) & 1) == 1,
           /* flag 4           */ ((hdr->flags >> 2) & 1) == 1,
           /* flag 5           */ ((hdr->flags >> 1) & 1) == 1,
           /* flag 6           */ ((hdr->flags >> 0) & 1) == 1,
           /* window size      */ ntohs(hdr->window_size),
           /* checksum         */ ntohs(hdr->checksum),
           /* urgent pointer   */ ntohs(hdr->urgent_pointer)
    );

    print_byte_block(extract_data_from_tcp_hdr((unsigned char*) hdr, data_size), data_size, "TCP: ");
}

/**
 * Pretty print ICMP header
 *
 * @param hdr - header data
 * @param data_size - header size
 */
void print_icmp_hdr(icmp_hdr *hdr, long data_size) {
    icmp_packets++;
    printf("ICMP:  ----- ICMP Header -----\n"
           "ICMP:\n"
           "ICMP:  Type = %d (%s)\n"
           "ICMP:  Code = %d\n"
           "ICMP:  Checksum = 0x%x\n"
           "ICMP:",
           /* type     */ hdr->type, get_icmp_type_string(hdr->type),
           /* code     */ hdr->code,
           /* checksum */ ntohs(hdr->checksum)
    );
}

/**
 * Pretty print IP header
 *
 * @param hdr - header data
 *
 * @param data_size - packet size
 */
void print_ip_hdr(ip_hdr *hdr, int data_size) {
    ip_packets++;
    printf("IP: ----- IP Header -----\n"
           "IP:\n"
           "IP: Version             = %d\n"
           "IP: Header length       = %d bytes\n"
           "IP: Type of service     = %d\n"
           "IP: ..%d. .... routine\n"
           "IP: ...%d .... normal delay\n"
           "IP: .... %d... normal throughput\n"
           "IP: .... .%d.. normal reliability\n"
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
            /* version          */ hdr->version,
            /* header length    */ hdr->length,
            /* type of service  */ hdr->type_of_service,
            /* flag 1           */ ((hdr->type_of_service >> 3) & 1) == 1,
            /* flag 2           */ ((hdr->type_of_service >> 2) & 1) == 1,
            /* flag 3           */ ((hdr->type_of_service >> 1) & 1) == 1,
            /* flag 4           */ ((hdr->type_of_service >> 0) & 1) == 1,
            /* total length     */ ntohs(hdr->total_length),
            /* identification   */ ntohs(hdr->identification),
            /* flags            */ hdr->flags & 0x4, (hdr->flags & 0x1) == (0x1), (hdr->flags & 0x2) == (0x2),
            /* fragment offset  */ ntohs(hdr->offset),
            /* time to live     */ hdr->time_to_live,
            /* protocol         */ hdr->proto, get_ip_proto_name(hdr->proto),
            /* checksum         */ ntohs(hdr->checksum),
            /* source addr      */ ip_addr_to_string(ntohl(hdr->source)),
            /* destination addr */ ip_addr_to_string(ntohl(hdr->destination))
    );

    // Unpack and print packet data
    if (get_current_tcp_hdr() != NULL) {
        print_tcp_hdr(get_current_tcp_hdr(), data_size - (int) sizeof(ip_hdr));
    } else if (get_current_udp_hdr() != NULL) {
        print_udp_hdr(get_current_udp_hdr(), data_size - (int) sizeof(ip_hdr));
    } else if (get_current_icmp_hdr() != NULL) {
        print_icmp_hdr(get_current_icmp_hdr(), data_size - (int) sizeof(ip_hdr));
    }
}

/**
 * Prints ARP Address
 *
 * @param hdr - header data
 * @param data_size - ARP packet size
 */
void print_arp_hdr(arp_hdr *hdr, long data_size) {
    arp_packets++;
    printf("ARP:  ----- ARP/RARP Frame -----\n"
           "ARP:\n"
           "ARP:  Hardware type = %d\n"
           "ARP:  Protocol type = %x (%s)\n"
           "ARP:  Length of hardware address = %d bytes\n"
           "ARP:  Length of protocol address = %d bytes\n"
           "ARP:  Opcode %d (%s)\n"
           "ARP:  Sender’s hardware address = %s\n"
           "ARP:  Sender’s protocol address = %s, %s\n"
           "ARP:  Target hardware address = %s\n"
           "ARP:  Target protocol address = %s, %s\n"
           "ARP:",
            /* Hardware type           */ ntohs(hdr->hardware_type),
            /* Protocol type           */ ntohs(hdr->protocol_type), get_eth_type_name(ntohs(hdr->protocol_type)),
            /* Hardware length         */ hdr->hardware_length,
            /* Protocol length         */ hdr->protocol_length, // TODO: translate OPCode
            /* OPCode                  */ ntohs(hdr->opcode), get_arp_opcode_string(ntohs(hdr->opcode)),
            /* Sender MAC Address      */ eth_addr_to_string(hdr->sender_mac), // TODO: translate Hostname
            /* Sender IP Address       */ ip_addr_to_string(hdr->sender_ip), "??",
            /* Destination MAC Address */ eth_addr_to_string(hdr->destination_mac),
            /* Destination IP Address  */ ip_addr_to_string(hdr->destination_ip), "??" // TODO: translate Hostname
    );
}

/**
 * Print Ethernet frame
 *
 * @param hdr - header data
 * @param data_size - frame size
 */
void print_eth_hdr(eth_hdr *hdr, long data_size) {
    eth_frames++;
    if(eth_is_broadcast(hdr)) eth_broadcasts++;

    int order = packet_count;
    long size = data_size;
    int type_number = ntohs(hdr->ether_type);
    char *type_name = get_eth_type_name(ntohs(hdr->ether_type));
    char *dst_addr = eth_addr_to_string(hdr->ether_dhost);
    char *src_addr = eth_addr_to_string(hdr->ether_shost);
    char *make = get_make_from_ether_addr(hdr->ether_shost);
    char *broadcast = (eth_is_broadcast(hdr)) ? ", (broadcast)" : "";
    printf("ETHER:  ----- Ethernet Header -----\n"
           "ETHER:\n"
           "ETHER:  Packet %d\n"
           "ETHER:  Packet size = %ld bytes\n"
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

    // If and IP header exists inside the frame print it
    if (get_current_ip_hdr() != NULL) {
        print_ip_hdr(get_current_ip_hdr(), current_eth_hdr_len - sizeof(eth_hdr));
    } else if (get_current_arp_hdr() != NULL) {
        print_arp_hdr(get_current_arp_hdr(), current_eth_hdr_len - sizeof(arp_hdr));
    }
}

/**
 * Process packet
 *
 * @param frame - ethernet frame
 * @param len - frame size
 */
void process(unsigned char *frame, long len) {
    // Check if frame is valid
    if (len == 0)
        return;

    // Cast packet data to Ethernet Header struct
    eth_hdr *eth = (eth_hdr *) frame;

    // Globally set current Ethernet header to be used to run filters
    set_eth_header(eth, len);

    // Check if packet should be filtered
    if (!is_filtered()) {
        accepted_packets++;
        sequential_rejected_packets = 0;

        printf("\r");
        print_eth_hdr(current_eth_hdr, len);

    } else {
        printf("\rPackets rejected in a row: %d", ++sequential_rejected_packets);
    }

    fflush(stdout);
}

/**
 * Setup signal handler
 *
 * @param signal - signal code
 */
void signal_handler(int signal) {
    printf("\n\n\n"
           "ethernet frames:       %d\n"
           "ethernet broadcast:    %d\n"
           "ARP                    %d\n"
           "IP                     %d\n"
           "ICMP                   %d\n"
           "UDP                    %d\n"
           "TCP                    %d\n"
           "To this host:          %d\n",
           eth_frames,
           eth_broadcasts,
           arp_packets,
           ip_packets,
           icmp_packets,
           udp_packets,
           tcp_packets,
           packet_count);

    // Continue signal propagation
    exit(signal);
}

/**
 * Register signal hnalder
 */
void register_signal_handler() {
    signal(SIGTERM, signal_handler);
}

/**
 * main
 */
int main(int argc, char **argv) {
    long n;
    int sockfd;
    unsigned char *packet_buffer;
    stack = malloc(sizeof(long) * MAX_FILTER_STACK);

    // Read parameters and filters
    process_parameters(argc, argv);
    register_signal_handler();

    if(is_filtered()) {
        printf("Filter returned: FILTERED\n");
    } else {
        printf("Filter returned: NOT FILTERED\n");
    }

    printf("Ended\n");

    return 0;
}

