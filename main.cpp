#include <pcap.h>
#include <stdio.h>
#include <cstring>
#include <string>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <map>





std::map<uint32_t, std::map<std::string, unsigned int> > endpoints_ipv4;
std::map<std::pair<uint32_t, uint32_t> , std::map<std::string, unsigned int> > conversations_ipv4;

std::map<std::string, std::map<std::string, unsigned int> > endpoints_eth;
std::map<std::pair<std::string, std::string> , std::map<std::string, unsigned int> > conversations_eth;

std::map<std::pair<uint32_t, uint16_t> , std::map<std::string, unsigned int> > endpoints_tcp;
std::map<std::pair<std::pair<uint32_t, uint16_t>, std::pair<uint32_t, uint16_t> > , std::map<std::string, unsigned int> > conversations_tcp;

std::map<std::pair<uint32_t, uint16_t> , std::map<std::string, unsigned int> > endpoints_udp;
std::map<std::pair<std::pair<uint32_t, uint16_t>, std::pair<uint32_t, uint16_t> > , std::map<std::string, unsigned int> > conversations_udp;

void usage() {
    printf("syntax: pcap-test <filename>\n");
    printf("sample: pcap-test test.pcap\n");
}

char* ntoh_hex(u_int8_t *addr, char* buf, int size)
{

    for(int i=0;i<size;i++)
    {
        snprintf(buf+(3*i),size, "%02x",addr[i]);
        if(i!=size-1)
            snprintf(buf+2+(3*i),2,":");

    }

    return buf;

}


void callback(u_char *user ,const struct pcap_pkthdr* header, const u_char* pkt_data ){

    struct ether_header *eth_hdr;
    struct ip *ipv4_hdr;




    eth_hdr = (struct ether_header*)pkt_data; //Ethernet header starting point.



    if(ntohs(eth_hdr->ether_type) == ETHERTYPE_IP){



        pkt_data+= sizeof(ether_header);
        ipv4_hdr = (struct ip*)pkt_data;



        //Endpoints IPv4
        auto itr = endpoints_ipv4.find(ipv4_hdr->ip_src.s_addr);
        if (itr != endpoints_ipv4.end()) {
            endpoints_ipv4[ipv4_hdr->ip_src.s_addr]["Tx Packets"]++;
            endpoints_ipv4[ipv4_hdr->ip_src.s_addr]["Tx Bytes"] += header->caplen;

        } else {

            std::map<std::string, unsigned int> mp;
            mp.insert({"Tx Packets",1});
            mp.insert({"Tx Bytes",header->caplen});
            mp.insert({"Rx Packets",0});
            mp.insert({"Rx Bytes",0});
            endpoints_ipv4.insert({ipv4_hdr->ip_src.s_addr,mp});
        }

        itr = endpoints_ipv4.find(ipv4_hdr->ip_dst.s_addr);
        if (itr != endpoints_ipv4.end()) {
            endpoints_ipv4[ipv4_hdr->ip_dst.s_addr]["Rx Packets"]++;
            endpoints_ipv4[ipv4_hdr->ip_dst.s_addr]["Rx Bytes"] += header->caplen;

        } else {

            std::map<std::string, unsigned int> mp;
            mp.insert({"Rx Packets",1});
            mp.insert({"Rx Bytes",header->caplen});
            mp.insert({"Tx Packets",0});
            mp.insert({"Tx Bytes",0});
            endpoints_ipv4.insert({ipv4_hdr->ip_dst.s_addr,mp});
        }



        //Conversations IPv4
        std::pair<uint32_t, uint32_t> pr = (ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr)
                ? std::make_pair(ipv4_hdr->ip_src.s_addr, ipv4_hdr->ip_dst.s_addr)
                : std::make_pair(ipv4_hdr->ip_dst.s_addr, ipv4_hdr->ip_src.s_addr);


        auto itr3 = conversations_ipv4.find(pr);

        if (itr3 != conversations_ipv4.end()) {
            if(ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr){
                conversations_ipv4[pr]["Packets A -> B"]++;
                conversations_ipv4[pr]["Bytes A -> B"] += header->caplen;
            }else{

                conversations_ipv4[pr]["Packets B -> A"]++;
                conversations_ipv4[pr]["Bytes B -> A"] += header->caplen;
            }
        }else{

            std::map<std::string, unsigned int> mp;
            if(ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr){
                mp.insert({"Packets A -> B",1});
                mp.insert({"Bytes A -> B",header->caplen});
                mp.insert({"Packets B -> A",0});
                mp.insert({"Bytes B -> A",0});
            }else{
                mp.insert({"Packets A -> B",0});
                mp.insert({"Bytes A -> B",0});
                mp.insert({"Packets B -> A",1});
                mp.insert({"Bytes B -> A",header->caplen});
            }
            conversations_ipv4.insert({pr,mp});
        }

        //Endpoints Ethernet
        std::string shost = std::string((char*)eth_hdr->ether_shost).substr(0,6);
        std::string dhost = std::string((char*)eth_hdr->ether_dhost).substr(0,6);


        auto itr2 = endpoints_eth.find(shost);
        if (itr2 != endpoints_eth.end()) {
            endpoints_eth[shost]["Tx Packets"]++;
            endpoints_eth[shost]["Tx Bytes"] += header->caplen;

        } else {

            std::map<std::string, unsigned int> mp;
            mp.insert({"Tx Packets",1});
            mp.insert({"Tx Bytes",header->caplen});
            mp.insert({"Rx Packets",0});
            mp.insert({"Rx Bytes",0});
            endpoints_eth.insert({shost,mp});
        }

        itr2 = endpoints_eth.find(dhost);
        if (itr2 != endpoints_eth.end()) {
            endpoints_eth[dhost]["Rx Packets"]++;
            endpoints_eth[dhost]["Rx Bytes"] += header->caplen;

        } else {

            std::map<std::string, unsigned int> mp;
            mp.insert({"Rx Packets",1});
            mp.insert({"Rx Bytes",header->caplen});
            mp.insert({"Tx Packets",0});
            mp.insert({"Tx Bytes",0});
            endpoints_eth.insert({dhost,mp});
        }

        //Conversations Ethernet
        std::pair<std::string, std::string> pr2 = shost.compare(dhost)<0
                ? std::make_pair(shost, dhost)
                : std::make_pair(dhost, shost);


        auto itr4 = conversations_eth.find(pr2);

        if (itr4 != conversations_eth.end()) {
            if(shost.compare(dhost)<0){
                conversations_eth[pr2]["Packets A -> B"]++;
                conversations_eth[pr2]["Bytes A -> B"] += header->caplen;
            }else{

                conversations_eth[pr2]["Packets B -> A"]++;
                conversations_eth[pr2]["Bytes B -> A"] += header->caplen;
            }
        }else{

            std::map<std::string, unsigned int> mp;
            if(shost.compare(dhost)<0){
                mp.insert({"Packets A -> B",1});
                mp.insert({"Bytes A -> B",header->caplen});
                mp.insert({"Packets B -> A",0});
                mp.insert({"Bytes B -> A",0});
            }else{
                mp.insert({"Packets A -> B",0});
                mp.insert({"Bytes A -> B",0});
                mp.insert({"Packets B -> A",1});
                mp.insert({"Bytes B -> A",header->caplen});
            }
            conversations_eth.insert({pr2,mp});
        }



        if(ipv4_hdr->ip_p == IPPROTO_TCP){


            struct tcphdr *tcp_hdr;
            pkt_data += ipv4_hdr->ip_hl * 4;
            tcp_hdr = (struct tcphdr*)pkt_data;



            //Endpoints TCP
            uint16_t sport = ntohs(tcp_hdr->source);
            uint16_t dport = ntohs(tcp_hdr->dest);

            std::pair<uint32_t, uint16_t> pr = std::make_pair(ipv4_hdr->ip_src.s_addr,sport);
            auto itr = endpoints_tcp.find(pr);
            if (itr != endpoints_tcp.end()) {
                endpoints_tcp[pr]["Tx Packets"]++;
                endpoints_tcp[pr]["Tx Bytes"] += header->caplen;

            } else {

                std::map<std::string, unsigned int> mp;
                mp.insert({"Tx Packets",1});
                mp.insert({"Tx Bytes",header->caplen});
                mp.insert({"Rx Packets",0});
                mp.insert({"Rx Bytes",0});
                endpoints_tcp.insert({pr,mp});
            }

            pr = std::make_pair(ipv4_hdr->ip_dst.s_addr,dport);
            itr = endpoints_tcp.find(pr);
            if (itr != endpoints_tcp.end()) {
                endpoints_tcp[pr]["Rx Packets"]++;
                endpoints_tcp[pr]["Rx Bytes"] += header->caplen;

            } else {

                std::map<std::string, unsigned int> mp;
                mp.insert({"Rx Packets",1});
                mp.insert({"Rx Bytes",header->caplen});
                mp.insert({"Tx Packets",0});
                mp.insert({"Tx Bytes",0});
                endpoints_tcp.insert({pr,mp});
            }


            //Conversations TCP
            std::pair<std::pair<uint32_t, uint16_t>, std::pair<uint32_t, uint16_t> > pr2 =
                    (ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr)
                    ? std::make_pair(std::make_pair(ipv4_hdr->ip_src.s_addr, sport)
                                     , std::make_pair(ipv4_hdr->ip_dst.s_addr, dport))
                    : std::make_pair(std::make_pair(ipv4_hdr->ip_dst.s_addr, dport)
                                     , std::make_pair(ipv4_hdr->ip_src.s_addr, sport));


            auto itr3 = conversations_tcp.find(pr2);

            if (itr3 != conversations_tcp.end()) {
                if(ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr){
                    conversations_tcp[pr2]["Packets A -> B"]++;
                    conversations_tcp[pr2]["Bytes A -> B"] += header->caplen;
                }else{

                    conversations_tcp[pr2]["Packets B -> A"]++;
                    conversations_tcp[pr2]["Bytes B -> A"] += header->caplen;
                }
            }else{

                std::map<std::string, unsigned int> mp;
                if(ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr){
                    mp.insert({"Packets A -> B",1});
                    mp.insert({"Bytes A -> B",header->caplen});
                    mp.insert({"Packets B -> A",0});
                    mp.insert({"Bytes B -> A",0});
                }else{
                    mp.insert({"Packets A -> B",0});
                    mp.insert({"Bytes A -> B",0});
                    mp.insert({"Packets B -> A",1});
                    mp.insert({"Bytes B -> A",header->caplen});
                }
                conversations_tcp.insert({pr2,mp});
            }




        }else if(ipv4_hdr->ip_p == IPPROTO_UDP){
            struct udphdr *udp_hdr;
            pkt_data += ipv4_hdr->ip_hl * 4;
            udp_hdr = (struct udphdr*)pkt_data;

            //Endpoints UDP
            uint16_t sport = ntohs(udp_hdr->source);
            uint16_t dport = ntohs(udp_hdr->dest);

            std::pair<uint32_t, uint16_t> pr = std::make_pair(ipv4_hdr->ip_src.s_addr,sport);
            auto itr = endpoints_udp.find(pr);
            if (itr != endpoints_udp.end()) {
                endpoints_udp[pr]["Tx Packets"]++;
                endpoints_udp[pr]["Tx Bytes"] += header->caplen;

            } else {

                std::map<std::string, unsigned int> mp;
                mp.insert({"Tx Packets",1});
                mp.insert({"Tx Bytes",header->caplen});
                mp.insert({"Rx Packets",0});
                mp.insert({"Rx Bytes",0});
                endpoints_udp.insert({pr,mp});
            }

            pr = std::make_pair(ipv4_hdr->ip_dst.s_addr,dport);
            itr = endpoints_udp.find(pr);
            if (itr != endpoints_udp.end()) {
                endpoints_udp[pr]["Rx Packets"]++;
                endpoints_udp[pr]["Rx Bytes"] += header->caplen;

            } else {

                std::map<std::string, unsigned int> mp;
                mp.insert({"Rx Packets",1});
                mp.insert({"Rx Bytes",header->caplen});
                mp.insert({"Tx Packets",0});
                mp.insert({"Tx Bytes",0});
                endpoints_udp.insert({pr,mp});
            }


            //Conversations UDP
            std::pair<std::pair<uint32_t, uint16_t>, std::pair<uint32_t, uint16_t> > pr2 =
                    (ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr)
                    ? std::make_pair(std::make_pair(ipv4_hdr->ip_src.s_addr, sport)
                                     , std::make_pair(ipv4_hdr->ip_dst.s_addr, dport))
                    : std::make_pair(std::make_pair(ipv4_hdr->ip_dst.s_addr, dport)
                                     , std::make_pair(ipv4_hdr->ip_src.s_addr, sport));


            auto itr3 = conversations_udp.find(pr2);

            if (itr3 != conversations_udp.end()) {
                if(ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr){
                    conversations_udp[pr2]["Packets A -> B"]++;
                    conversations_udp[pr2]["Bytes A -> B"] += header->caplen;
                }else{

                    conversations_udp[pr2]["Packets B -> A"]++;
                    conversations_udp[pr2]["Bytes B -> A"] += header->caplen;
                }
            }else{

                std::map<std::string, unsigned int> mp;
                if(ipv4_hdr->ip_src.s_addr < ipv4_hdr->ip_dst.s_addr){
                    mp.insert({"Packets A -> B",1});
                    mp.insert({"Bytes A -> B",header->caplen});
                    mp.insert({"Packets B -> A",0});
                    mp.insert({"Bytes B -> A",0});
                }else{
                    mp.insert({"Packets A -> B",0});
                    mp.insert({"Bytes A -> B",0});
                    mp.insert({"Packets B -> A",1});
                    mp.insert({"Bytes B -> A",header->caplen});
                }
                conversations_udp.insert({pr2,mp});
            }

        }


    }


}




int main(int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return -1;
    }

    char errbuf[PCAP_ERRBUF_SIZE];






    pcap_t* handle = pcap_open_offline(argv[1], errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_offline(%s) return NULL - %s\n", argv[1], errbuf);
        return -1;
    }



    int ret = pcap_loop(handle, -1, callback, NULL );
    if (ret == -1 || ret == -2) {
        printf("pcap_next_ex return %d(%s)\n", ret, pcap_geterr(handle));
        pcap_close(handle);
        return -1;
    }
    pcap_close(handle);




    in_addr st;
    printf("Endpoints-IPv4\n\n");
    for(auto i : endpoints_ipv4){
        st.s_addr = i.first;
        printf("Address :\t%s\n", inet_ntoa(st) );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");


    char buf[20];
    printf("Endpoints-Ethernet\n\n");
    for(auto i : endpoints_eth){
        printf("Address :\t%s\n", ntoh_hex((uint8_t*)i.first.c_str(),buf,6) );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }


    printf("=======================================================================\n\n");

    printf("Endpoints-tcp\n\n");
    for(auto i : endpoints_tcp){
        st.s_addr = i.first.first;
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(st), i.first.second );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");

    printf("Endpoints-udp\n\n");
    for(auto i : endpoints_udp){
        st.s_addr = i.first.first;
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(st), i.first.second );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");

    printf("Conversations-IPv4\n\n");
    for(auto i : conversations_ipv4){
        st.s_addr = i.first.first;
        printf("Address A :\t%s\t", inet_ntoa(st) );
        st.s_addr = i.first.second;
        printf("Address B :\t%s\n", inet_ntoa(st) );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");


    printf("Conversations-Ethernet\n\n");
    for(auto i : conversations_eth){
        printf("Address A :\t%s\nAddress B :\t%s\n"
               , ntoh_hex((uint8_t*)i.first.first.c_str(),buf,6), ntoh_hex((uint8_t*)i.first.second.c_str(),buf,6) );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");

    printf("Conversations-tcp\n\n");
    for(auto i : conversations_tcp){
        st.s_addr = i.first.first.first;
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(st), i.first.first.second );
        st.s_addr = i.first.second.first;
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(st), i.first.second.second );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");


    printf("Conversations-udp\n\n");
    for(auto i : conversations_udp){
        st.s_addr = i.first.first.first;
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(st), i.first.first.second );
        st.s_addr = i.first.second.first;
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(st), i.first.second.second );
        for(auto j : i.second){
            printf("%s :\t%u\n", j.first.c_str(), j.second);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");

    return 0;

}
