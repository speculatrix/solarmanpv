// solarmansniff

// this is yet another attempt to discover the solarmanpv protocol by sniffing
// the traffic between a Sofar HYD5000ES inverter and Solarman's service.
// the long term aim is to be able to write a main in the middle proxy which
// the inverter and solarman, and write the logged data to a local store as
// well as having it visible in solarman; thus, if Solarman goes away or
// they start charging an excessive fee, it will be possible to run your
// own monitoring.
// also, having the values may make it possible to make your inverter talk to
// an EV smart charger or hot water controller etc, rather than buy a Zappi
// and Eddi.

// standard linux things
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

// needed for htons:
#include <netinet/in.h>

#include <net/ethernet.h>

// /usr/src/netinet/ stuff, don't mix with /usr/include/linux/* stuff!
//include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>

// special libraries
#include <pcap.h>


// constants
#define PKTMAX          65536
#define PROMISC_FLAG    1


// globals
int shutdown_requested = 0;
char *if_name = NULL;        // Name of interface (e.g. eth0, wlan0)


// constants
#define SM_LEN_INVERTER_ID  16
#define SM_LEN_LOGGER_ID    4
#define SM_LEN_IPV4         15

// the inverter sends different packet sizes to solarman but only those with
// a payload of 202 bytes seem to contain information we care about.
// this is the format of packets of length 202
typedef struct {
        u_char  c0__a5,                             // always a5
                c1__bd,                             // always bd
                c2__00,                             // always 00
                c3__10,                             // always 10?
                c4__42,                             // always 42?
                c5,                                 // unknown
                c6;                                 // unknown
        u_char  logger_id[SM_LEN_LOGGER_ID];        // c7-c10
        u_char  c11_c31[21];                        // unknowns
        u_char  inverter_id[SM_LEN_INVERTER_ID];    // c32-c47 space padded string
        u_char  c48_c71[24];                        // unknowns
        u_char  battery_charge;                     // c72
        u_char  c73;                                // unknown
        u_char  battery_temperature;                // c74
        u_char  c75;                                // ipv4 flag is 0xf0?
        u_char  logger_ipv4[SM_LEN_IPV4];           // c76 to 91
        u_char  c92_c201[112];                      // unknowns
} sm_202_t;

/////////////////////////////////////////////////////////////////////////////
// this function understands the layout of the solarman packets
int     solarman_dump(
        u_char      *payload,
        unsigned    length
        )
{

    if (length == 202) {
        if (*payload != 0xa5 || *(payload +  1) != 0xbd) {
            printf("Error, solarman_dump unknown sman proto with length 202, started 0x%02x 0x%02x\n", *payload, *(payload +  1));
            return(1);
        }

        // unpack the payload
        sm_202_t   *sm_202 = (sm_202_t *)payload;
        printf("inverter id '%.*s'\n", SM_LEN_INVERTER_ID, sm_202->inverter_id);

        printf("Guess: battery charge %d, battery temperature %d\n", sm_202->battery_charge, sm_202->battery_temperature);

        printf("logger id offset is %d\n", ( (u_char *)sm_202->logger_id) - payload);
        unsigned long my_logger_id = ((unsigned long) sm_202->logger_id[3]) << 24
                                   | ((unsigned long) sm_202->logger_id[2]) << 16
                                   | ((unsigned long) sm_202->logger_id[1]) << 8
                                   | ((unsigned long) sm_202->logger_id[0])     ;
        printf("Logger ID: %ld\n", my_logger_id);

        char logger_ipv4[SM_LEN_IPV4 + 1];
        if (sm_202->c75 == 0xf0) {
            snprintf(logger_ipv4, SM_LEN_IPV4, "%s", sm_202->logger_ipv4);
            printf("Logger IPv4 is %s\n", logger_ipv4);
        } else {
            printf("c75 contained 0x%lx so no ipv4 address in the field\n", sm_202->c75);
        }

    } else {
        printf("Error, solarman_dump unknown sman proto, length not 202\n");
    }

    fflush(stdout);

}

/////////////////////////////////////////////////////////////////////////////
void    usage(char *argv0) {
    printf("Usage: %s <device> <port>\n", argv0);
}

/////////////////////////////////////////////////////////////////////////////
void sigkill_handler(int sig_num) {
    printf("sigkill\n");
    shutdown_requested = 1;
}

/////////////////////////////////////////////////////////////////////////////
char *get_now() {

   time_t rawtime;
   struct tm *info;
   time( &rawtime );
   info = localtime( &rawtime );
   return(asctime(info));

}

/////////////////////////////////////////////////////////////////////////////
void    print_hex_dotted(
        unsigned char *byte_ptr,    // ptr to array of bytes
        unsigned count,             // how many bytes
        char *join_str,             // separator/joiner char
        char *end_str               // end of line or something
        ) {

    for (unsigned i = 0; i < count; ++i) {
        printf("%02x", *(byte_ptr + i));
        if (i < count - 1)
            printf("%s", join_str);
    }

    if (end_str)
        printf("%s", end_str);
}
/////////////////////////////////////////////////////////////////////////////
void    print_dec_dotted(
        unsigned char *byte_ptr,    // ptr to array of bytes
        unsigned count,             // how many bytes
        char *join_str,             // separator/joiner char
        char *end_str               // end of line or something
        ) {

    for (unsigned i = 0; i < count; ++i) {
        printf("%02d", *(byte_ptr + i));
        if (i < count - 1)
            printf("%s", join_str);
    }

    if (end_str)
        printf("%s", end_str);
}

/////////////////////////////////////////////////////////////////////////////
// callback function for pcap_loop
void    got_packet(
        u_char                      *args,
        const struct pcap_pkthdr    *pkthdr,
        const u_char                *pkt
        ) {



    if (pkt == NULL) {
        printf("Null packet");
        return;
    }
    //printf("got_packet on if_name %s, caplen %u, len %u, %s\n", if_name, pkthdr->caplen, pkthdr->len, get_now());

    //printf("packet header: ");
    //print_hex_dotted((char *) pkthdr, sizeof(struct pcap_pkthdr), " ", "\n");
    //printf("packet at 0x%llx: ", pkt);
    //print_hex_dotted((char *) pkt, pkthdr->len, " ", "\n");

    struct iphdr *ipHdr = 0;
    struct ip6_hdr *ip6Hdr = 0;

    // find the IP datagram in the sniffed packet
    // FIXME make it work with ipv6
    if (!strncmp(if_name, "ppp", 3)) {
        printf("guess that IP is directly in the payload\n");
        ipHdr = (struct iphdr *) pkt;
    } else {
        struct ether_header *ethHdr = (struct ether_header *) (pkt);
        printf("Dbg, ether packet received, src ");
        print_hex_dotted(ethHdr->ether_shost, ETH_ALEN, ":", NULL);
        printf(", dest ");
        print_hex_dotted(ethHdr->ether_dhost, ETH_ALEN, ":", NULL);
        printf(", ether type 0x%x\n", ethHdr->ether_type);

        unsigned ether_type = htons(ethHdr->ether_type);
        if (ether_type == ETH_P_IP) {
            //printf("Dbg, decoding ipv4 header\n");
            ipHdr = (struct iphdr *) (pkt + sizeof(struct ether_header));
        }
        else if (ether_type == ETH_P_IPV6) {
            printf("Dbg, eth proto 0x%x, ipv6\n", ETH_P_IPV6);
        } else {
            printf("Dbg, unknown ether proto 0x%x\n", ethHdr->ether_type);
        }

    }

    // find the tcp payload
    //struct ether_header *ethHdr = (struct ether_header *) (pkt);
    struct tcphdr *tcpHdr;

    if (ipHdr) {
        unsigned iph_size = ipHdr->ihl * 4;
        //printf("ipHdr at 0x%llx, iph_size %d \n", ipHdr, iph_size);
        if (iph_size < 20) {
            printf("Error, invalid IP header len %u bytes\n", iph_size);
            return;
        }

        // FIXME make it work with ipv6
        if (ipHdr->version == 4) {
            //printf("Dbg, IPv4 found\n");
            if (ipHdr->protocol == 6) {
                tcpHdr = (struct tcphdr *) (pkt + sizeof(struct ether_header) + iph_size);
                //printf("tcpHdr at 0x%llx: \n", tcpHdr);

                printf("Dbg, tcp src %u, dst %u\n", ntohs(tcpHdr->source), ntohs(tcpHdr->dest));

                const unsigned char *data_ptr = pkt + sizeof(struct ether_header) + iph_size + tcpHdr->th_off * 4;
                unsigned payload_size = pkthdr->len - (data_ptr - pkt);
                printf("packet payload at 0x%llx length %u: ", data_ptr, payload_size);
                if (payload_size) {
                    print_hex_dotted((unsigned char *)data_ptr, payload_size, " ", "\n");
                    solarman_dump((unsigned char *)data_ptr, payload_size);
                } else {
                    printf("\n");
                }
            }
            else {
                printf("Dbg, ignoring ip proto %d packet\n", ipHdr->protocol);
            }
        } else if (ipHdr->version == 6) {
            printf("Dbg, IPv6 found\n");
        } else {
            printf("Error, IPv%d found\n", ipHdr->version);
            exit;
        }
    }

    printf("\n");
}

/////////////////////////////////////////////////////////////////////////////
int main(int argc, char *argv[]) {

    // user params
    //char *if_name;            // Name of interface (e.g. eth0, wlan0)
    //char *proto = "tcp";  // it only uses tcp
    char *proto = "ip";     // it only uses ipv4
    char *port_str;         // port number as string

    // process parameters
    if (argc > 2) {
        if_name = argv[1];
        port_str = argv[2];
    }
    else {
        usage(argv[0]);
        return(1);
    }


    printf("if_name %s proto %s port %s\n", if_name, proto, port_str);

    // assemble ascii filter for proto and port
    int     filter_str_len = strlen(proto) + strlen(" and port ") + strlen(port_str) + 1;
    char    pcap_filter_exp[filter_str_len + 1];
    snprintf(pcap_filter_exp, filter_str_len, "%s and port %s", proto, port_str);
    printf("pcap filter is %s, filter_str_len %d\n", pcap_filter_exp, filter_str_len);


    // open the pcap library
    pcap_t  *pcapHandle;
    //int timeout = 0;                        // wait indefinitely
    int timeout = 1;                        // wait
    char pcap_err_buff[PCAP_ERRBUF_SIZE];    // Size defined in pcap.h
    pcapHandle = pcap_open_live(if_name, PKTMAX, PROMISC_FLAG, timeout, pcap_err_buff);
    if (pcapHandle == NULL) {
        printf("Error, failed to open libpcap: %s\n", pcap_err_buff);
        return(1);
    }


    // get interface IP values
    bpf_u_int32 net;
    bpf_u_int32 mask;
     if (pcap_lookupnet(if_name, &net, &mask, pcap_err_buff) == -1) {
        printf("Warning, can't get net/netmask for device %s, error '%s'\n", if_name, pcap_err_buff);
        //return(1);
    }
    else {
        printf("net ");
        print_dec_dotted((unsigned char *) &net, 4, ".", NULL);
        printf(", mask ");
        print_dec_dotted((unsigned char *) &mask, 4, ".", NULL);
        printf("\n");
    }

    // compile the packet filter
    struct bpf_program fp;
   if (pcap_compile(pcapHandle, &fp, pcap_filter_exp, 1, mask) == -1)
    {
        printf("Error, can't compile filter expression '%s', error '%s'", pcap_filter_exp, pcap_geterr(pcapHandle));
        return(1);
    }

    if (pcap_setfilter(pcapHandle, &fp) == -1)
    {
        printf("Error, can't apply filter expression, error '%s'", pcap_geterr(pcapHandle));
        return(1);
    }

    //printf("Debug, sizeof ether_header %d\n", sizeof(struct ether_header));
    //printf("Debug, min sizeof ipHdr %d\n", sizeof(struct iphdr));
    //printf("Debug, min sizeof tcpHdr %d\n", sizeof(struct tcphdr));
    printf("Debug, sizeof sm_202_t %d\n", sizeof(sm_202_t));

    //signal(SIGINT, sigkill_handler);

    // sniff forever (-1)
    while (!shutdown_requested) {
        pcap_loop(pcapHandle, -1, got_packet, (u_char *) NULL);
        printf("pcap_loop shutdown_requested loop\n");
    }

    pcap_close(pcapHandle);

    return(0);
}

// vim: tabstop=8 expandtab shiftwidth=4 softtabstop=4
