/*
author - piyush
*/

#include "packet_reader.h"

/* Used internally to identify packet type*/
enum FLAG { SYN, SYNACK, ACK, FIN, RST, EMPTY, UNKNOWN};
/* Data-structure to hold the packet/conn states*/
map<u_int32_t , struct host_node> host_connection_map;


/* Ctrl + c to exit*/
void sigproc(int x)
{        
    signal(SIGINT, sigproc);
    /* NOTE some versions of UNIX will reset signal to default
    after each call. So for portability reset signal each time */
    printf("*********Statistics***********\n");
    REP(iter, host_connection_map){
        struct host_node node = iter->second;
        printf("Source IP : %s\n", inet_ntoa(*(struct in_addr*)(&(node.source_ip))));
        printf("Total packets sent : %lu\n", node.packets_sent);
        printf("Final AnamolyScore : %d\n", node.anamoly_score);
        printf("Successful handshakes :%d\n", node.total_succ_connections);
        printf("Half open connection : %d\n", node.total_half_open);
        printf("Reset connection : %d\n\n", node.total_reset);
    }
    printf("*********Exit***********\n");
    exit(0);
}

void debug_print(char* m){
    #ifdef DEBUG
      printf("%s\n",m);
    #endif
}

struct host_node init_host_node(struct host_node host, u_int32_t host_source_ip){
    host.source_ip = host_source_ip;
    host.total_succ_connections = 0;
    host.total_half_open = 0;
    host.total_reset = 0;
    host.anamoly_score = 0;
    memset(host.dest_port_tracker, 0, sizeof(host.dest_port_tracker));
    host.last_connection_time = 0;
    host.packets_sent = 0;
    return host;
}

struct connection make_connection(
    const u_int32_t source_ip, const u_int source_port,
    const u_int32_t dest_ip, const u_int dest_port){

    struct connection* conn = 
        (struct connection*) malloc(sizeof(struct connection));
    conn->source_ip = source_ip;
    conn->source_port = source_port;
    conn->dest_ip = dest_ip;
    conn->dest_ip = dest_port;
    conn->is_conn_init= false;
    conn->is_conn_active =false;
    conn->state = 0;
    return *conn;
}

long long form_key( u_short source_port, 
    u_int32_t dest_ip, u_short dest_port){
    //Change this later to something better
    return source_port + dest_ip + dest_port;
}

time_t get_current_time(){
    time_t t;
    time(&t);
    return t;
}

void alert(struct host_node node, int anamoly_score, int count){
    printf("*******Potential portscan********\n");
    printf("%s\n", inet_ntoa(*(struct in_addr*)&node.source_ip));
    printf("Anamoly Score :%d\n", anamoly_score);
    printf("Succ handshake :%d\n", node.total_succ_connections);
    printf("Half conn :%d\n", node.total_half_open);
    printf("Linearly scanned dest ports:%d\n\n", count);
    return;
}

/* Add all the custom anamoly detection logic here
   Also made any needed changes to the node, as it passed by ref    
*/
void run_anamoly_scan(struct host_node& node, int inc_anamoly_score){
    
    //First check if the host is doing a linear scan or not
    int new_anamoly_score = 0;
    int prev_anamoly_score = node.anamoly_score;
    time_t prev_connection_time  = node.last_connection_time;
    time_t current_time = get_current_time();
    double factor = 0.0 ;
    int count = 0 ;
    for(int i=0;i<(1<<16);i++){
        if(node.dest_port_tracker[i] == 1)
            count++;
    }

    if( count > LINEAR_PORT_SCAN_THRESHOLD){
        alert(node, prev_anamoly_score, count);
        memset(node.dest_port_tracker, 0 ,sizeof(node.dest_port_tracker));
    }

    //okay, this is gonna get complex now :)
    time_t curr_window_beg = current_time - VALID_WINDOW_SEC;
    if( prev_connection_time - curr_window_beg > 0){
        factor = ((double)(prev_connection_time - curr_window_beg)) / VALID_WINDOW_SEC ; 
    }
    //printf("Factor :%f\n\n", factor);
    new_anamoly_score =  (factor*prev_anamoly_score) + inc_anamoly_score;
   
    if( new_anamoly_score > ANAMOLY_SCORE_THRESHOLD){
        alert(node, new_anamoly_score, count);
        new_anamoly_score = 0;
    }

    node.last_connection_time = current_time;
    node.anamoly_score = new_anamoly_score;
  
    return;
}

/* Update the internal state of the system with this packet*/
void update_system_with_packet(
    const u_int32_t source_ip,
    const u_short source_port,
    const u_int32_t dest_ip,
    const u_short dest_port,
    const FLAG f){

    long long key = form_key(source_port, dest_ip, dest_port);
    /* Populate connections in map in not already present */
    if (host_connection_map.find(source_ip)== host_connection_map.end()){ 
        struct host_node node; node = init_host_node(node, source_ip);
        node.port_connmap[key] = 
            make_connection(source_ip, source_port,dest_ip,dest_port);
        host_connection_map[source_ip] = node;        

    }else{
        map<long long, struct connection> portmap = host_connection_map[source_ip].port_connmap;
        if(portmap.find(key) == portmap.end()){
            portmap[key] = 
                make_connection(source_ip, source_port,dest_ip,dest_port);
            host_connection_map[source_ip].port_connmap = portmap;
        }
    }

    //Just a sanity check!!
    assert(host_connection_map.find(source_ip)!=host_connection_map.end());

    struct host_node node = host_connection_map[source_ip];
    struct connection conn = node.port_connmap[key];
    bool remove_conn = false;
    int curr_anamoly_score_change = 0;
    if(f == SYN){
        if(conn.is_conn_init){
            // This maybe a re-transmission 
            //remove_conn = true;
            curr_anamoly_score_change+=1;
            debug_print("Syn on open conn detected");
        }else if(conn.is_conn_init== false){ // trying to make a new connection
            conn.source_ip = source_ip;
            conn.dest_ip = dest_ip;
            conn.source_port = source_port;
            conn.dest_port= dest_port;
            conn.is_conn_init = true;
            conn.state = 1;
            curr_anamoly_score_change+=10;
        }
    }else if (f==SYNACK){
        if(conn.is_conn_init && conn.state==1){
            conn.state = 2;
            node.total_half_open+=1;
            curr_anamoly_score_change+=10; 
        }else{
            remove_conn = true;
            curr_anamoly_score_change+=1;
            debug_print("Invalid SynAck detected");
        }
    }else if(f==ACK){
        if(conn.is_conn_active){
            //valid data transfer,every pack is ACK, skip
        }else if(conn.is_conn_init && conn.state==2){
            conn.state = 3;
            conn.is_conn_active = true; //make connection active
            node.total_half_open-=1;
            node.total_succ_connections++;
            curr_anamoly_score_change-=20;
            debug_print("Anamoly score decremented");
        }else{
            /*  
            Might be part of an existing connection or
            This might be an anamolous ack(?) or a fin ack, do nothing
            */
            remove_conn = true;
        }
    }else if (f == FIN){
        remove_conn = true;
        if(!conn.is_conn_active){ //possible fin scan happening
            curr_anamoly_score_change+= 15;
            debug_print("Fin on closed connection detected");
        }
    }else if (f == RST){
        remove_conn =true;
        if(conn.is_conn_active){
            //valid case of resetting connection
            node.total_reset++;
        }else{ //Now it might be possible that the attacker has sent a syn and 
            // the listener replied with RST. Possible syn attack
            if(host_connection_map.find(dest_ip)!=host_connection_map.end()){
                map<long long, struct connection> conmap = host_connection_map[dest_ip].port_connmap;
                if(conmap.find(form_key(dest_port, source_ip,source_port))!= conmap.end()){
                    struct connection con = conmap[form_key(dest_port, source_ip,source_port)];
                    if(con.is_conn_init && con.state==1){
                        //Possible rst from close port in reply to a SYN
                        host_connection_map[dest_ip].anamoly_score+= 10;
                        run_anamoly_scan(host_connection_map[dest_ip], 10);
                    }
                }
            }else{
                curr_anamoly_score_change+=1;
                debug_print("RST on unopened connection detected");
            }
        }
    }else if( f == EMPTY){
        if(!conn.is_conn_init){ //fin scan happening with empty packet
            curr_anamoly_score_change+=10;
            remove_conn = true;
            debug_print("Empty flag packet detected");
        }else{
            //this means connection was initiated and we got an empty packet
            //Can be a tranmission error or something
        }
    }
    
    /* Now update the source port tracker array, just to check 
      if that host is linearly scanning the ports 
    */
    
    //this means the port connected to was probably a listening server port            
    node.dest_port_tracker[dest_port] = 1;
    node.packets_sent++; //this will be slightly incorrect for SYNACK, change later

    if(remove_conn){
        map<long long , struct connection>::iterator it = node.port_connmap.find(key);
        node.port_connmap.erase(it);
    }else{
        node.port_connmap[key] = conn;    
    }
    //printf("%d\n", node.anamoly_score);
    //printf("Done processing %s packet with score: %d and flag :%d\n", inet_ntoa(*((struct in_addr*)&source_ip)), node.anamoly_score, f);
  
   // this method would make any needed anamoly changes to the node
    run_anamoly_scan(node, curr_anamoly_score_change);
    host_connection_map[source_ip] = node;
    return;
}

/* Method to consume the packet, update the maps and possible detect port scan */
void consume_packet(
    const struct in_addr source_ip, const u_short source_port,
    const struct in_addr dest_ip, const u_short dest_port, const u_char flag){

    /* 
    1. Find the packet type : Considering these 5 types now - SYN,SYNACK,ACK,RST,FIN
    2. Set the source and destination ip's according to packet type 
    */
    u_int32_t final_source = source_ip.s_addr;
    u_int32_t final_dest = dest_ip.s_addr;
    u_short final_source_port = source_port;
    u_short final_dest_port = dest_port;
    bool swap = false;
    bool possible_portscan = false;
    FLAG f = UNKNOWN;

    if(flag&TH_SYN){
        if(flag&TH_ACK){
            f = SYNACK;
            swap = true;
        }else{
            f = SYN;
        }
    }else if (flag&TH_ACK){ //this means not syn and ack
        f = ACK;
    } else if(flag&TH_RST) { //not syn, not synack, not ack maybe rst
        f = RST;
        possible_portscan = true; //if no connection is already open
    } else if(flag&TH_FIN){
        f = FIN;
        possible_portscan = true; // if no connection is already open
    }else if (flag == 0){
        f = EMPTY;
        possible_portscan = true;
    }else{//don't care for now
        f = UNKNOWN;
        possible_portscan = true;
    }
    
    if(swap){ //Only for synack for now, check this:)
        final_source = dest_ip.s_addr;
        final_source_port = dest_port;
        final_dest = source_ip.s_addr;
        final_dest_port = source_port;
    }

    update_system_with_packet(final_source, final_source_port, final_dest, final_dest_port, f);   

}//end of function

/* Packet handler */
void disassemble_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet){
    
    const struct sniff_ethernet *ethernet; /* The ethernet header */
    const struct sniff_ip *ip; /* The IP header */
    const struct sniff_tcp *tcp; /* The TCP header */
    const u_char *payload; /* Packet payload */

    u_int size_ip; 
    u_int size_tcp;
    ethernet = (struct sniff_ethernet*)(packet);
    ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20) {
        printf("   * Invalid IP header length: %u bytes\n", size_ip);
        return;
    }
    tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
    size_tcp = TH_OFF(tcp)*4;
    if (size_tcp < 20) {
        printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
        return;
    }
    payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);
    consume_packet(ip->ip_src, tcp->th_sport,ip->ip_dst, tcp->th_dport, tcp->th_flags);
    return;
}

int main(int argc, char *argv[])
{   
    signal(SIGINT, sigproc);
    pcap_t *handle;         /* Session handle */
    char *dev;          /* The device to sniff on */
    char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
    struct bpf_program fp;      /* The compiled filter */
    char filter_exp[] = "tcp";  /* The filter expression */
    bpf_u_int32 mask;       /* Our netmask */
    bpf_u_int32 net;        /* Our IP */
    struct pcap_pkthdr header;  /* The header that pcap gives us */
    const u_char *packet;       /* The actual packet */

    /* Define the device */
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL) {
        fprintf(stderr, "Couldn't find default device: %s\n", errbuf);
        return(2);
    }
    /* Find the properties for the device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
        net = 0;
        mask = 0;
    }
    /* Open the session in promiscuous mode */
    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
        return(2);
    }
    /* Compile and apply the filter */
    if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        fprintf(stderr, "Couldn't install filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return(2);
    }
    printf("******************************\n");
    printf("Sniffing on device :%s\n", dev);
    printf("%s\n", "Starting packet sniffing loop");
    printf("Running with anamoly threshold :%d\n", ANAMOLY_SCORE_THRESHOLD);
    printf("******************************\n\n");
    int val = pcap_loop(handle, -1, disassemble_packet, NULL);
    printf("%d\n", val); 
    /* And close the session */
    pcap_close(handle);
    return(0);
}
    
