#include <pcap/pcap.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include "uthash.h"

typedef struct IPMAC_pair { // MAINLY USED FOR ARP SPOOF ANALYSIS
  char *mac_addr; /*key*/
  char *ip_addr;
  UT_hash_handle hh;
} IPMAC_pair;

IPMAC_pair *known_pairs_table = NULL;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6

/* Ethernet header */
struct sniff_ethernet {
  u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
  u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
  u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
  u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
  u_char  ip_tos;                 /* type of service */
  u_short ip_len;                 /* total length */
  u_short ip_id;                  /* identification */
  u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* dont fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
  u_char  ip_ttl;                 /* time to live */
  u_char  ip_p;                   /* protocol */
  u_short ip_sum;                 /* checksum */
  struct in_addr ip_src;  /* source and dest address */
  struct in_addr ip_dst;
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
  u_short th_sport;               /* source port */
  u_short th_dport;               /* destination port */
  tcp_seq th_seq;                 /* sequence number */
  tcp_seq th_ack;                 /* acknowledgement number */
  u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
  u_char  th_flags;
        #define TH_FIN  0x01
        #define TH_SYN  0x02
        #define TH_RST  0x04
        #define TH_PUSH 0x08
        #define TH_ACK  0x10
        #define TH_URG  0x20
        #define TH_ECE  0x40
        #define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;                 /* window */
  u_short th_sum;                 /* checksum */
  u_short th_urp;                 /* urgent pointer */
};

char* parseMac(const u_char* raw_mac) { 
  char* ret = (char *)malloc( sizeof(char) * 18 ); 
  sprintf( ret, "%02x:%02x:%02x:%02x:%02x:%02x", raw_mac[0], raw_mac[1], raw_mac[2], raw_mac[3], raw_mac[4], raw_mac[5] ); 
  return ret;
} 

void loadKnownPairs( void ) {

  IPMAC_pair *tmp;

  tmp = (IPMAC_pair *)malloc( sizeof( IPMAC_pair ) );
  tmp->ip_addr = "192.168.0.100";
  tmp->mac_addr = "7c:d1:c3:94:9e:b8";
  HASH_ADD_KEYPTR( hh, known_pairs_table, tmp->mac_addr, strlen(tmp->mac_addr), tmp );

  tmp = (IPMAC_pair *)malloc( sizeof( IPMAC_pair ) );
  tmp->ip_addr = "192.168.0.103";
  tmp->mac_addr = "d8:96:95:01:a5:c9";
  HASH_ADD_KEYPTR( hh, known_pairs_table, tmp->mac_addr, strlen(tmp->mac_addr), tmp );

  tmp = (IPMAC_pair *)malloc( sizeof( IPMAC_pair ) );
  tmp->ip_addr = "192.168.0.1";
  tmp->mac_addr = "f8:1a:67:cd:57:6e";
  HASH_ADD_KEYPTR( hh, known_pairs_table, tmp->mac_addr, strlen(tmp->mac_addr), tmp );

}

int main( int argc, char **argv ) {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *pcap_handle;
  struct bpf_program filter;
  IPMAC_pair *lookup = NULL;
  const u_char *pkt;
  struct pcap_pkthdr *hdr;
  char *buf, *sip, *dip;
  int pktcount = 0;
  const struct sniff_ethernet *ethernet; /* The ethernet header */
  const struct sniff_ip *ip; /* The IP header */
  const struct sniff_tcp *tcp; /* The TCP header */
  const char *payload; /* Packet payload */

  u_int size_ip;
  u_int size_tcp;

  loadKnownPairs();

  printf( "Initializing packet analysis for ARP Spoofing\n" );
  printf( "Retrieving handle\n" );
  pcap_handle = pcap_open_offline( argv[1], errbuf );
  if ( pcap_handle == NULL ) {
    fprintf( stderr, "Could not open file\n" );
    exit(1);
  }
  printf( "Retrieving next packet\n" );

  for ( pktcount = 1; pcap_next_ex( pcap_handle, &hdr, &pkt ) == 1; pktcount++ ) {

    ethernet = (struct sniff_ethernet*)(pkt);

    switch ( ntohs(ethernet->ether_type) ) {
    case ETHERTYPE_ARP:
      //printf( "###### ARP PACKET: %d ######\n", pktcount );
      ip = (struct sniff_ip*)(pkt + SIZE_ETHERNET + 2);
      size_ip = IP_HL(ip)*4;
      tcp = (struct sniff_tcp*)(pkt + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      payload = (u_char *)(pkt + SIZE_ETHERNET + size_ip + size_tcp);
      buf = inet_ntoa( ip->ip_src );
      sip = malloc(strlen(buf)+1);
      strcpy(sip,buf);
      buf = inet_ntoa( *( (struct in_addr*)((u_char*)&(ip->ip_src)+10)) ); 
      dip = malloc(strlen(buf)+1); 
      strcpy(dip, buf);
      //printf("IP source \t %s \t %s\n",sip,getMac(ethernet->ether_shost)); 
      //printf("IP dest \t %s \t %s\n",dip,getMac(ethernet->ether_dhost));

      HASH_FIND_STR( known_pairs_table, parseMac(ethernet->ether_shost), lookup );
      if ( strcmp( lookup->ip_addr, sip ) != 0 ) {
	printf( "!!!!!!!!!!!!!!! ARP SPOOFING !!!!!!!!!!!!!!\n" );
	printf( "Packet No. %d\n", pktcount );
	printf( "Offending MAC Address: %s\n", parseMac(ethernet->ether_shost) );
	printf( "Claimed IP: %s\n", sip );
	printf( "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!\n\n" );
      }
      break;
    
    case ETHERTYPE_IP:
      //printf( "####### IP PACKET: %d ######\n", pktcount );
      ip = (struct sniff_ip*)(pkt + SIZE_ETHERNET );
      size_ip = IP_HL(ip)*4;
      tcp = (struct sniff_tcp*)(pkt + SIZE_ETHERNET + size_ip);
      size_tcp = TH_OFF(tcp)*4;
      payload = (u_char *)(pkt + SIZE_ETHERNET + size_ip + size_tcp);
      buf = inet_ntoa( ip->ip_src );
      sip = malloc(strlen(buf)+1);
      strcpy(sip,buf);
      buf = inet_ntoa( ip->ip_dst ); 
      dip = malloc(strlen(buf)+1); 
      strcpy(dip, buf);
      //printf("%d: IP source \t %s \t %s\n",pktcount,sip,getMac(ethernet->ether_shost)); 
      //printf("IP dest \t %s \t %s\n",dip,getMac(ethernet->ether_dhost));
      //printf("Src port: %d, Dst port: %d\n\n", ntohs(tcp->th_sport), ntohs(tcp->th_dport) );

      break;
    }
  }

}
