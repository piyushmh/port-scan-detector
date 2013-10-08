/*
author - piyush
*/

#include <pcap.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <assert.h>
#include <memory.h>
#include <time.h>
#include <signal.h>
#include <map>
#include <iostream>

using namespace std;

//#define DEBUG  //uncomment this for debugging statements
#define ETHER_ADDR_LEN  6 /* Ethernet addresses are 6 bytes */
#define SIZE_ETHERNET 14 /*Ethernet packet size */
#define ANAMOLY_SCORE_THRESHOLD 240
#define LINEAR_PORT_SCAN_THRESHOLD 55 
#define VALID_WINDOW_SEC 300
#define REP(i,m) for(typeof(m.begin()) i = (m.begin()); i!= (m.end());i++)



/* This is added so that code compiles, it is not recognizing
    tcp_seq so I am just assuming an 32 bit integer  
http://stackoverflow.com/questions/6842897/c-expected-specifier-qualifier-list-before-tcp-seq */
typedef u_int32_t tcp_seq;

/* Ethernet header */
struct sniff_ethernet {
    u_char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address */
    u_char ether_shost[ETHER_ADDR_LEN]; /* Source host address */
    u_short ether_type; /* IP? ARP? RARP? etc */
};

/* IP header */
struct sniff_ip {
    u_char ip_vhl;      /* version << 4 | header length >> 2 */
    u_char ip_tos;      /* type of service */
    u_short ip_len;     /* total length */
    u_short ip_id;      /* identification */
    u_short ip_off;     /* fragment offset field */
    #define IP_RF 0x8000        /* reserved fragment flag */
    #define IP_DF 0x4000        /* dont fragment flag */
    #define IP_MF 0x2000        /* more fragments flag */
    #define IP_OFFMASK 0x1fff   /* mask for fragmenting bits */
    u_char ip_ttl;      /* time to live */
    u_char ip_p;        /* protocol */
    u_short ip_sum;     /* checksum */
    struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)       (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)        (((ip)->ip_vhl) >> 4)

/* TCP header */
struct sniff_tcp {
    u_short th_sport;   /* source port */
    u_short th_dport;   /* destination port */
    tcp_seq th_seq;     /* sequence number */
    tcp_seq th_ack;     /* acknowledgement number */

    u_char th_offx2;    /* data offset, rsvd */
    #define TH_OFF(th)  (((th)->th_offx2 & 0xf0) >> 4)
    u_char th_flags;
    #define TH_FIN 0x01
    #define TH_SYN 0x02
    #define TH_RST 0x04
    #define TH_PUSH 0x08
    #define TH_ACK 0x10
    #define TH_URG 0x20
    #define TH_ECE 0x40
    #define TH_CWR 0x80
    #define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;     /* window */
    u_short th_sum;     /* checksum */
    u_short th_urp;     /* urgent pointer */
};


struct connection{
    u_int32_t source_ip;
    u_int32_t dest_ip;
    u_short source_port;
    u_short dest_port;
    bool is_conn_init; //on if state >0 
    bool is_conn_active;//on if state > 2
    int state;
    /* States - 
    0 - DEAD
    1 - SYN
    2 - SYNACK
    3 - ACK
    4 - FIN_INITIATED
    5 - FIN_ACKNOWLEDGED
    6 - RST TEARDOWN
    */
    void print(){
        printf("Source id : %s, source_port : %d\n", inet_ntoa(*(struct in_addr*)(&source_ip)), source_port);
        printf("Dest id : %s, dest : %d\n", inet_ntoa(*(struct in_addr*)(&dest_ip)), dest_port);
        printf("Is_conn_init :%d\n", is_conn_init);
        printf("Is_conn_open :%d\n", is_conn_active);
        printf("State :%d\n", state);    
    }
}; 

struct host_node{
    u_int32_t source_ip;
    // this contains conction per port of the host
    map<long long, struct connection> port_connmap; 
    int total_succ_connections;
    int total_half_open;
    int total_reset;
    int anamoly_score;
    int dest_port_tracker[1<<16];
    time_t last_connection_time;
    long long packets_sent;

    void print(){
        printf("Source ip : %s\n", inet_ntoa(*(struct in_addr*)(&source_ip)));
        printf("AnamolyScore : %d\n", anamoly_score);
        printf("Successful handshakes :%d\n", total_succ_connections);
        printf("Half open connection : %d\n", total_half_open);
        for(map<long long,struct connection>::iterator iter = port_connmap.begin(); iter!= port_connmap.end(); iter++){
            printf("Source key :%llu\nStarting map\n", iter->first);
            (iter->second).print();
        }
    }
};
