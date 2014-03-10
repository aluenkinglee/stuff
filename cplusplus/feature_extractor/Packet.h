#ifndef PACKET_H
#define PACKET_H
#include <iostream>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <pcap.h>
#include <algorithm>
#include <vector>
#include <cstring>
#include "macro.h"

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)
#define TH_OFF(th)              (((th)->th_offx2 & 0xf0) >> 4)

using namespace std;
// ethernet packet
struct packet_ethernet
{
    u_char  ether_dhost[ETHER_ADDR_LEN];      /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];      /* source host address */
    u_short ether_type;                       /* IP? ARP? RARP? etc */
};
typedef class Packet_ethernet
{
private:
    packet_ethernet header;
    u_char *packet;
public:
    Packet_ethernet(struct packet_ethernet& pe)
    {
        _copy(&pe);
    }
    Packet_ethernet(struct packet_ethernet* pe)
    {
        _copy(pe);
    }
    Packet_ethernet(const u_char *packet)
    {
        packet_ethernet* pe = (struct packet_ethernet*)(packet);
        _copy(pe);
    }
    virtual ~Packet_ethernet();
public:
    packet_ethernet get_ethernet()
    {
        return header;
    }
private:
    void _copy(struct packet_ethernet* pe)
    {
        std::copy(header.ether_dhost,
             header.ether_dhost+ETHER_ADDR_LEN,
             pe->ether_dhost);
        std::copy(header.ether_shost,
             header.ether_shost+ETHER_ADDR_LEN,
             pe->ether_shost);
        header.ether_type  = pe->ether_type;
    }
} Packet_ethernet;


// IP header
struct packet_ip
{
    u_char  ip_vhl;                   	//  version << 4 | header length >> 2
    u_char  ip_tos;                   	//  type of service
    u_short ip_len;                   	//  total length
    u_short ip_id;                    	//  identification
    u_short ip_off;                   	//  fragment offset field
    u_char  ip_ttl;                   	//  time to live
    u_char  ip_p;                     	//  protocol (see http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
    u_short ip_sum;                   	//  checksum
    struct in_addr ip_src;           	//  source address
    struct in_addr ip_dst;           	//  dest address
};

typedef class Packet_ip
{
private:
    packet_ip header;
    typedef size_t size_type;
    size_type size_ip;
public:
    Packet_ip(const u_char *packet)
    {
        const struct packet_ip   *ip;
        ip = (struct packet_ip*)(packet + SIZE_ETHERNET);
        size_ip = IP_HL(ip) * 4;
        _copy(*ip);
    }
    Packet_ip(const Packet_ip& other)
    {
        memcpy(&(this->header),&other.header,sizeof(packet_ip));
        this->size_ip = other.size_ip;
    }
    Packet_ip& operator=(const Packet_ip& other)
    {
        memcpy(&(this->header), &other.header, sizeof(packet_ip));
        this->size_ip = other.size_ip;
        return *this;
    }
public:
    size_type size()
    {
        return this->size_ip;
    }
    size_t get_protocal()
    {
        return this->header.ip_p;
    }
    char* source_ip()
    {
        return inet_ntoa(this->header.ip_src);
    }
    char* dest_ip()
    {
        return inet_ntoa(this->header.ip_dst);
    }
    size_t ip_length()
    {
        return this->header.ip_len;
    }
private:
    void _copy(const struct packet_ip& pi)
    {
        header.ip_vhl = pi.ip_vhl;
        header.ip_tos = pi.ip_tos;
        header.ip_len = pi.ip_len;
        header.ip_id  = pi.ip_id;
        header.ip_off = pi.ip_off;
        header.ip_p   = pi.ip_p;
        header.ip_sum = pi.ip_sum;
        header.ip_src = pi.ip_src;
        header.ip_dst = pi.ip_dst;
    }
}Packet_ip;


typedef u_int tcp_seq;
typedef struct packet_tcp
{
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
    u_char  th_flags;
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
} packet_tcp,tcp_header;
typedef class Packet_tcp
{
private:
    packet_tcp header;
    u_char* packet;
    u_char* payload;
    size_t size_tcp;

public:
    Packet_tcp(const struct pcap_pkthdr *header, const u_char *packet)
    {
        const struct packet_tcp *tcp;
        Packet_ip ip(packet);

        this->packet = new u_char[header->len];
        memcpy(this->packet, packet, header->len);
        //注意这里指向了外面的packet
        //this->packet = packet;
        tcp = (struct packet_tcp*)(packet + SIZE_ETHERNET + ip.size());
        _copy(tcp);
    }

private:
    void _copy(const struct packet_tcp *pt)
    {
        header.th_sport = pt->th_sport;
        header.th_dport = pt->th_dport;
        header.th_seq   = pt->th_seq;
        header.th_ack   = pt->th_ack;
        header.th_offx2 = pt->th_offx2;
        header.th_flags = pt->th_flags;
        header.th_win   = pt->th_win;
        header.th_sum   = pt->th_sum;
        header.th_urp   = pt->th_urp;
        size_tcp = TH_OFF(pt)*4;
    }

public:
    void set_payload(u_char *packet)
    {
        Packet_ip ip(packet);
        this->packet = packet;
        this->payload = (u_char *)(packet + SIZE_ETHERNET + ip.size() + this->size_tcp);
    }
    size_t size()
    {
        return this->size_tcp;
    }
    int sport()
    {
        return ntohs(this->header.th_sport);
    }
    int dport()
    {
        return ntohs(this->header.th_dport);
    }
    size_t payload_length()
    {
        Packet_ip ip(this->packet);
        return ntohs(ip.ip_length()) - (ip.size() + this->size_tcp);
    }
    u_char get_flags()
    {
        return this->header.th_flags;
    }
}Packet_tcp;

typedef struct udp_header
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
} udp_header;

#endif // PACKET_H
