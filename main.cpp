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
#include <tuple>
#include "main.h"

#define reverse_pair(pr) std::make_pair(pr.second, pr.first)
#define reverse_tp(tp) std::make_tuple(std::get<2>(tp),std::get<3>(tp),std::get<0>(tp),std::get<1>(tp))



typedef std::map<uint32_t, EP_Value > Endpoint_ipv4;
Endpoint_ipv4 endpoints_ipv4;

typedef std::map<std::pair<uint32_t, uint32_t> , Flow_Value > Flows_ipv4;
Flows_ipv4 flows_ipv4;

typedef std::map<Mac, EP_Value> Endpoints_eth;
Endpoints_eth endpoints_eth;

typedef std::map<std::pair<Mac, Mac> , Flow_Value > Flows_eth;
Flows_eth flows_eth;

typedef std::map<std::pair<uint32_t, uint16_t> , EP_Value > Endpoints_tcp;
Endpoints_tcp endpoints_tcp;

typedef std::map<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>, Flow_Value > Flows_tcp;
Flows_tcp flows_tcp;

typedef std::map<std::pair<uint32_t, uint16_t> , EP_Value > Endpoints_udp;
Endpoints_udp endpoints_udp;

typedef std::map<std::tuple<uint32_t, uint16_t, uint32_t, uint16_t>, Flow_Value > Flows_udp;
Flows_udp flows_udp;




void usage() {
    printf("syntax: packet-stat <filename>\n");
    printf("sample: packet-stat test.pcap\n");
}

char* hex(u_int8_t *addr, char* buf, int size)
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
            itr->second.Tx_Packets++;
            itr->second.Tx_Bytes += header->caplen;

        } else {

            EP_Value ev = {1, header->caplen, 0, 0};
            endpoints_ipv4.insert({ipv4_hdr->ip_src.s_addr,ev});
        }

        itr = endpoints_ipv4.find(ipv4_hdr->ip_dst.s_addr);
        if (itr != endpoints_ipv4.end()) {
            itr->second.Rx_Packets++;
            itr->second.Rx_Bytes += header->caplen;

        } else {

            EP_Value ev = {0, 0, 1, header->caplen};
            endpoints_ipv4.insert({ipv4_hdr->ip_dst.s_addr,ev});
        }



        //Flows IPv4
        std::pair<uint32_t, uint32_t> pr
                = std::make_pair(ipv4_hdr->ip_src.s_addr, ipv4_hdr->ip_dst.s_addr);


        auto itr3 = flows_ipv4.find(pr);

        if (itr3 != flows_ipv4.end()) {
            itr3->second.Packets++;
            itr3->second.Bytes += header->caplen;

        }else{

            Flow_Value fv = {1, header->caplen };
            flows_ipv4.insert({pr, fv});
        }


        //Endpoints Ethernet
        Mac shost = Mac((uint8_t*)eth_hdr->ether_shost);
        Mac dhost = Mac((uint8_t*)eth_hdr->ether_dhost);


        auto itr2 = endpoints_eth.find(shost);
        if (itr2 != endpoints_eth.end()) {
            itr2->second.Tx_Packets++;
            itr2->second.Tx_Bytes += header->caplen;

        } else {

            EP_Value ev = {1, header->caplen, 0, 0};
            endpoints_eth.insert({shost,ev});
        }

        itr2 = endpoints_eth.find(dhost);
        if (itr2 != endpoints_eth.end()) {
            itr2->second.Rx_Packets++;
            itr2->second.Rx_Bytes += header->caplen;

        } else {

            EP_Value ev = { 0, 0, 1, header->caplen};
            endpoints_eth.insert({dhost,ev});
        }

        //Flows Ethernet
        std::pair<Mac, Mac> pr2 = std::make_pair(shost, dhost);


        auto itr4 = flows_eth.find(pr2);

        if (itr4 != flows_eth.end()) {
            itr4->second.Packets++;
            itr4->second.Bytes += header->caplen;

        }else{

            Flow_Value fv = {1, header->caplen};
            flows_eth.insert({pr2,fv});
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
                itr->second.Tx_Packets++;
                itr->second.Tx_Bytes += header->caplen;

            } else {

                EP_Value ev = {1, header->caplen, 0, 0};
                endpoints_tcp.insert({pr,ev});
            }

            pr = std::make_pair(ipv4_hdr->ip_dst.s_addr,dport);
            itr = endpoints_tcp.find(pr);
            if (itr != endpoints_tcp.end()) {
                itr->second.Rx_Packets++;
                itr->second.Rx_Bytes += header->caplen;

            } else {

                EP_Value ev = { 0, 0 , 1, header->caplen};
                endpoints_tcp.insert({pr,ev});
            }


            //Flows TCP
            std::tuple<uint32_t, uint16_t, uint32_t, uint16_t> tp
                    = std::make_tuple(ipv4_hdr->ip_src.s_addr, sport, ipv4_hdr->ip_dst.s_addr, dport);


            auto itr3 = flows_tcp.find(tp);

            if (itr3 != flows_tcp.end()) {
                itr3->second.Packets++;
                itr3->second.Bytes+= header->caplen;

            }else{

                Flow_Value fv = {1, header->caplen};
                flows_tcp.insert({tp,fv});
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
                itr->second.Tx_Packets++;
                itr->second.Tx_Bytes += header->caplen;

            } else {

                EP_Value ev = {1, header->caplen, 0, 0};
                endpoints_udp.insert({pr,ev});
            }

            pr = std::make_pair(ipv4_hdr->ip_dst.s_addr,dport);
            itr = endpoints_udp.find(pr);
            if (itr != endpoints_udp.end()) {
                itr->second.Rx_Packets++;
                itr->second.Rx_Bytes += header->caplen;

            } else {

                EP_Value ev = { 0, 0 , 1, header->caplen};
                endpoints_udp.insert({pr,ev});
            }


            //Flows UDP
            std::tuple<uint32_t, uint16_t, uint32_t, uint16_t> tp
                    = std::make_tuple(ipv4_hdr->ip_src.s_addr, sport, ipv4_hdr->ip_dst.s_addr, dport);


            auto itr3 = flows_udp.find(tp);

            if (itr3 != flows_udp.end()) {
                itr3->second.Packets++;
                itr3->second.Bytes+= header->caplen;

            }else{

                Flow_Value fv = {1, header->caplen};
                flows_udp.insert({tp,fv});

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





    printf("Endpoints-IPv4\n\n");
    for(auto i : endpoints_ipv4){

        printf("Address :\t%s\n", inet_ntoa(*(struct in_addr*)&i.first) );

        printf("Tx_Packets :\t%u\n", i.second.Tx_Packets);
        printf("Tx_Bytes :\t%u\n", i.second.Tx_Bytes);
        printf("Rx_Packets :\t%u\n", i.second.Rx_Packets);
        printf("Rx_Bytes :\t%u\n", i.second.Rx_Bytes);

        printf("\n");
    }
    printf("=======================================================================\n\n");


    char buf[20];
    printf("Endpoints-Ethernet\n\n");
    for(auto i : endpoints_eth){
        printf("Address :\t%s\n", hex((uint8_t*)i.first,buf,6) );
        printf("Tx_Packets :\t%u\n", i.second.Tx_Packets);
        printf("Tx_Bytes :\t%u\n", i.second.Tx_Bytes);
        printf("Rx_Packets :\t%u\n", i.second.Rx_Packets);
        printf("Rx_Bytes :\t%u\n", i.second.Rx_Bytes);
        printf("\n");
    }


    printf("=======================================================================\n\n");

    printf("Endpoints-tcp\n\n");
    for(auto i : endpoints_tcp){
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(*(struct in_addr*)&i.first.first), i.first.second );
        printf("Tx_Packets :\t%u\n", i.second.Tx_Packets);
        printf("Tx_Bytes :\t%u\n", i.second.Tx_Bytes);
        printf("Rx_Packets :\t%u\n", i.second.Rx_Packets);
        printf("Rx_Bytes :\t%u\n", i.second.Rx_Bytes);
        printf("\n");
    }
    printf("=======================================================================\n\n");

    printf("Endpoints-udp\n\n");
    for(auto i : endpoints_udp){
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(*(struct in_addr*)&i.first.first), i.first.second );
        printf("Tx_Packets :\t%u\n", i.second.Tx_Packets);
        printf("Tx_Bytes :\t%u\n", i.second.Tx_Bytes);
        printf("Rx_Packets :\t%u\n", i.second.Rx_Packets);
        printf("Rx_Bytes :\t%u\n", i.second.Rx_Bytes);
        printf("\n");
    }
    printf("=======================================================================\n\n");

    printf("Conversations-IPv4\n\n");
    for(auto i : flows_ipv4){
        printf("Address A :\t%s\t", inet_ntoa(*(struct in_addr*)&i.first.first));
        printf("Address B :\t%s\n", inet_ntoa(*(struct in_addr*)&i.first.second));
        printf("Packets A->B :\t%u\n", i.second.Packets);
        printf("Bytes A->B :\t%u\n", i.second.Bytes);

        auto itr = flows_ipv4.find(reverse_pair(i.first));
        if(itr != flows_ipv4.end()){
            printf("Packets B->A :\t%u\n", itr->second.Packets);
            printf("Bytes B->A :\t%u\n", itr->second.Bytes);
        }else{
            printf("Packets B->A :\t%u\n", 0);
            printf("Bytes B->A :\t%u\n", 0);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");


    printf("Conversations-Ethernet\n\n");
    for(auto i : flows_eth){
        printf("Address A :\t%s\n", hex((uint8_t*)i.first.first,buf,6));
        printf("Address B :\t%s\n", hex((uint8_t*)i.first.second,buf,6));

        printf("Packets A->B :\t%u\n", i.second.Packets);
        printf("Bytes A->B :\t%u\n", i.second.Bytes);

        auto itr = flows_eth.find(reverse_pair(i.first));
        if(itr != flows_eth.end()){
            printf("Packets B->A :\t%u\n", itr->second.Packets);
            printf("Bytes B->A :\t%u\n", itr->second.Bytes);
        }else{
            printf("Packets B->A :\t%u\n", 0);
            printf("Bytes B->A :\t%u\n", 0);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");

    printf("Conversations-tcp\n\n");
    for(auto i : flows_tcp){
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(*(struct in_addr*)&std::get<0>(i.first)), std::get<1>(i.first) );
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(*(struct in_addr*)&std::get<2>(i.first)), std::get<3>(i.first) );

        printf("Packets A->B :\t%u\n", i.second.Packets);
        printf("Bytes A->B :\t%u\n", i.second.Bytes);

        auto itr = flows_tcp.find(reverse_tp(i.first));
        if(itr != flows_tcp.end()){
            printf("Packets B->A :\t%u\n", itr->second.Packets);
            printf("Bytes B->A :\t%u\n", itr->second.Bytes);
        }else{
            printf("Packets B->A :\t%u\n", 0);
            printf("Bytes B->A :\t%u\n", 0);
        }
        printf("\n");
    }
    printf("=======================================================================\n\n");


    printf("Conversations-udp\n\n");
    for(auto i : flows_udp){

        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(*(struct in_addr*)&std::get<0>(i.first)), std::get<1>(i.first) );
        printf("Address :\t%s\tPort :\t%u\n", inet_ntoa(*(struct in_addr*)&std::get<2>(i.first)), std::get<3>(i.first) );

        printf("Packets A->B :\t%u\n", i.second.Packets);
        printf("Bytes A->B :\t%u\n", i.second.Bytes);

        auto itr = flows_udp.find(reverse_tp(i.first));
        if(itr != flows_udp.end()){
            printf("Packets B->A :\t%u\n", itr->second.Packets);
            printf("Bytes B->A :\t%u\n", itr->second.Bytes);
        }else{
            printf("Packets B->A :\t%u\n", 0);
            printf("Bytes B->A :\t%u\n", 0);

        }
        printf("\n");
    }
    printf("=======================================================================\n\n");

    return 0;


}
