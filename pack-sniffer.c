#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <linux/if_ether.h>
#include <linux/filter.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <ctype.h>
#include <time.h>

// Maps transport protocol number to its name
char* transport_protocol(unsigned int code) {
    switch(code) {
        case 1: return "ICMP";
        case 2: return "IGMP";
        case 6: return "TCP";
        case 17: return "UDP";
        default: return "UNKNOWN";
    }
}

// Prints a line of payload in both hexadecimal and ASCII
void print_hex_ascii_line(const unsigned char *payload, int len, int offset) {
    int i;
    int gap;
    const unsigned char *ch;

    printf("%05d   ", offset); // Print the offset

    ch = payload;
    for (i = 0; i < len; i++) {
        printf("%02x ", *ch); // Print each byte in hex
        ch++;
        if (i == 7)
            printf(" "); // Add extra space after 8th byte for readability
    }

    if (len < 8)
        printf(" ");
    if (len < 16) {
        gap = 16 - len;
        for (i = 0; i < gap; i++) {
            printf("   "); // Fill the rest of the line with spaces
        }
    }
    printf("   ");

    ch = payload;
    for (i = 0; i < len; i++) {
        if (isprint(*ch))
            printf("%c", *ch); // Print printable characters
            else
                printf("."); // Replace non-printable characters with a dot
                ch++;
    }

    printf("\n");
}

// Prints the payload in hex and ASCII, line by line
void print_payload(const unsigned char *payload, int len) {
    int len_rem = len;
    int line_width = 16; // Number of bytes per line
    int line_len;
    int offset = 0;
    const unsigned char *ch = payload;

    if (len <= 0)
        return;

    if (len <= line_width) {
        print_hex_ascii_line(ch, len, offset);
        return;
    }

    while (1) {
        line_len = line_width % len_rem;
        print_hex_ascii_line(ch, line_len, offset);
        len_rem = len_rem - line_len;
        ch = ch + line_len;
        offset = offset + line_width;
        if (len_rem <= line_width) {
            print_hex_ascii_line(ch, len_rem, offset);
            break;
        }
    }
}

// Parses the captured packet and prints the headers and payload
void parse_packet(unsigned char *buffer, int size) {
    unsigned char *ethhead, *iphead, *tcphead, *udphead, *payload;
    ethhead = buffer;

    // Print Ethernet header
    printf("Ethernet Header\n");
    printf("   |-Source MAC Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           ethhead[0], ethhead[1], ethhead[2], ethhead[3], ethhead[4], ethhead[5]);
    printf("   |-Destination MAC Address: %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n",
           ethhead[6], ethhead[7], ethhead[8], ethhead[9], ethhead[10], ethhead[11]);

    iphead = buffer + 14; // IP header starts after Ethernet header (14 bytes)

    if (*iphead == 0x45) { // Check for IPv4 and no options
        printf("IP Header\n");
        printf("   |-Source IP Address: %d.%d.%d.%d\n",
               iphead[12], iphead[13], iphead[14], iphead[15]);
        printf("   |-Destination IP Address: %d.%d.%d.%d\n",
               iphead[16], iphead[17], iphead[18], iphead[19]);

        int ip_header_length = (iphead[0] & 0x0F) * 4; // Calculate IP header length
        int protocol = iphead[9];
        printf("   |-Protocol: %s\n", transport_protocol(protocol));

        if (protocol == 6) { // TCP
            tcphead = iphead + ip_header_length;
            printf("TCP Header\n");
            printf("   |-Source Port: %d\n", (tcphead[0] << 8) + tcphead[1]);
            printf("   |-Destination Port: %d\n", (tcphead[2] << 8) + tcphead[3]);
            payload = tcphead + 20; // TCP header is typically 20 bytes
        } else if (protocol == 17) { // UDP
            udphead = iphead + ip_header_length;
            printf("UDP Header\n");
            printf("   |-Source Port: %d\n", (udphead[0] << 8) + udphead[1]);
            printf("   |-Destination Port: %d\n", (udphead[2] << 8) + udphead[3]);
            payload = udphead + 8; // UDP header is 8 bytes
        } else {
            payload = iphead + ip_header_length; // For other protocols
        }

        int payload_length = size - (payload - buffer); // Calculate payload length
        printf("Payload (%d bytes):\n", payload_length);

        // Print payload in hex and ASCII
        print_payload(payload, payload_length);
    }
}

int main(int argc, char **argv) {
    int sock, n;
    char buffer[2048];

    // Create a raw socket
    if ((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_IP))) < 0) {
        perror("socket");
        exit(1);
    }

    // Bind the socket to a specific network interface
    const char *opt = "wlan0"; // Change this to your network interface
    if (setsockopt(sock, SOL_SOCKET, SO_BINDTODEVICE, opt, strlen(opt) + 1) < 0) {
        perror("setsockopt bind device");
        close(sock);
        exit(1);
    }

    // Set the interface to promiscuous mode
    struct ifreq ethreq;
    strncpy(ethreq.ifr_name, opt, IF_NAMESIZE);
    if (ioctl(sock, SIOCGIFFLAGS, &ethreq) == -1) {
        perror("ioctl SIOCGIFFLAGS");
        close(sock);
        exit(1);
    }
    ethreq.ifr_flags |= IFF_PROMISC;
    if (ioctl(sock, SIOCSIFFLAGS, &ethreq) == -1) {
        perror("ioctl SIOCSIFFLAGS");
        close(sock);
        exit(1);
    }

    // Attach a BPF to the socket to filter packets
    struct sock_filter BPF_code[] = {
        { 0x28, 0, 0, 0x0000000c }, // Load the EtherType
        { 0x15, 0, 5, 0x000086dd }, // Jump if EtherType is IPv6
        { 0x30, 0, 0, 0x00000014 }, // Load the IP protocol byte
        { 0x15, 6, 0, 0x00000006 }, // Jump if protocol is TCP
        { 0x15, 0, 6, 0x0000002c }, // Jump if protocol is IPv6 TCP
        { 0x30, 0, 0, 0x00000036 }, // Load the IP protocol byte for IPv6
        { 0x15, 3, 4, 0x00000006 }, // Jump if protocol is TCP
        { 0x15, 0, 3, 0x00000800 }, // Jump if EtherType is IP
        { 0x30, 0, 0, 0x00000017 }, // Load the IP protocol byte
        { 0x15, 0, 1, 0x00000006 }, // Jump if protocol is TCP
        { 0x6, 0, 0, 0x00040000 }, // Accept the packet
        { 0x6, 0, 0, 0x00000000 }  // Reject the packet
    };
    struct sock_fprog Filter;
    Filter.len = sizeof(BPF_code) / sizeof(BPF_code[0]);
    Filter.filter = BPF_code;

    if (setsockopt(sock, SOL_SOCKET, SO_ATTACH_FILTER, &Filter, sizeof(Filter)) < 0) {
        perror("setsockopt attach filter");
        close(sock);
        exit(1);
    }

    // Packet capture loop
    while (1) {
        printf("\n-------------------------------\n\n");

        // Get and print the current timestamp
        struct timespec ts;
        clock_gettime(CLOCK_REALTIME, &ts);
        char time_buf[100];
        strftime(time_buf, sizeof time_buf, "%Y-%m-%d %H:%M:%S", localtime(&ts.tv_sec));
        printf("Timestamp: %s.%09ld\n", time_buf, ts.tv_nsec);

        // Capture a packet
        n = recvfrom(sock, buffer, 2048, 0, NULL, NULL);
        printf("%d bytes read\n", n);

        if (n < 42) { // Minimum packet size for Ethernet + IP + TCP/UDP header
            perror("recvfrom():");
            printf("Incomplete packet (errno is %d)\n", errno);
            close(sock);
            exit(0);
        }

        // Parse and print the packet
        parse_packet((unsigned char*)buffer, n);
    }
}
