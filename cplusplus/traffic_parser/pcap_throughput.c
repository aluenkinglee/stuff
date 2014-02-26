//  feature extractor
//https://code.google.com/p/pcapsctpspliter/issues/detail?id=6
//   reads in a pcap file and outputs basic throughput statistics

#include <stdio.h>
#include <stdlib.h>
#include <ctime>

#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#include <pcap.h>

#define SNAP_LEN 1518       // 以太网帧最大长度
#define SIZE_ETHERNET 14   // 以太网包头长度 mac: 6*2 + type: 2 = 14
#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6  // mac地址长度
#endif

// defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

// ethernet packet
struct packet_ethernet
{
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                       /* IP? ARP? RARP? etc */
};

// IP header
struct packet_ip
{
    u_char  ip_vhl;                   	//  version << 4 | header length >> 2
    u_char  ip_tos;                   	//  type of service
    u_short ip_len;                   	//  total length
    u_short ip_id;                    	//  identification
    u_short ip_off;                   	//  fragment offset field
#define IP_RF 0x8000              	//  reserved fragment flag
#define IP_DF 0x4000              	//  dont fragment flag
#define IP_MF 0x2000              	//  more fragments flag
#define IP_OFFMASK 0x1fff		//  mask for fragmenting bits
    u_char  ip_ttl;                   	//  time to live
    u_char  ip_p;                     	//  protocol (see http://en.wikipedia.org/wiki/List_of_IP_protocol_numbers)
    u_short ip_sum;                   	//  checksum
    struct in_addr ip_src;           	//  source address
    struct in_addr ip_dst;           	//  dest address
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

typedef struct packet_tcp
{
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
} packet_tcp,tcp_header;

typedef struct udp_header
{
    u_short uh_sport;
    u_short uh_dport;
    u_short uh_len;
    u_short uh_sum;
} udp_header;


void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 0;                       // 包计数器
    const struct packet_ethernet *ethernet;     /* The ethernet header [1] */
    const struct packet_ip *ip;                 /* The IP header */
    const struct packet_tcp *tcp;               /* The TCP header */
    const struct udp_header *udp;
    u_char *payload;                          /* Packet payload */

    int size_ip;
    int size_tcp;
    int size_udp;
    int size_payload;

    count++;

    /* 以太网头 */
    ethernet = (struct packet_ethernet*)(packet);

    /* IP头 */
    ip = (struct packet_ip*)(packet + SIZE_ETHERNET);
    size_ip = IP_HL(ip)*4;
    if (size_ip < 20)
    {
        printf("无效的IP头长度: %u bytes\n", size_ip);
        return;
    }

    // if ( ip->ip_p != IPPROTO_TCP )  // TCP,UDP,ICMP,IP
    // {
    //     return;
    // }
    switch (ip->ip_p)
    {
    case IPPROTO_TCP:
    {
        /* TCP头 */
        tcp = (struct packet_tcp*)(packet + SIZE_ETHERNET + size_ip);
        size_tcp = TH_OFF(tcp)*4;
        if (size_tcp < 20)
        {
            printf("无效的TCP头长度: %u bytes\n", size_tcp);
            return;
        }

        int sport =  ntohs(tcp->th_sport);
        int dport =  ntohs(tcp->th_dport);

        printf("%s:%d -> ", inet_ntoa(ip->ip_src), sport);
        printf("%s:%d ", inet_ntoa(ip->ip_dst), dport);

        printf("%d ",ip->ip_p);
        //内容
        payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

        //内容长度
        size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

        if (size_payload > 0)
        {
            //printf("%d bytes:\n", size_payload, payload);
            printf("%u %d %d %d %d bytes\n", header->len,ntohs(tcp->th_seq), ntohs(tcp->th_ack), ntohs(tcp->th_flags)&(TH_SYN), size_payload );
            //write(payload, size_payload);
        }
        else
        {
            printf("%u %u %u %d \n", header->len,ntohs(tcp->th_seq), ntohs(tcp->th_ack),ntohs(tcp->th_win));
        }
        break;
    }

    case IPPROTO_UDP:
    {
        udp = (udp_header*) (packet + SIZE_ETHERNET + size_ip);
        size_udp = 8;// see http://6152587.blog.51cto.com/6142587/1229425

        int sport =  ntohs(udp->uh_sport);
        int dport =  ntohs(udp->uh_dport);

        printf("%s:%d -> ", inet_ntoa(ip->ip_src), sport);
        printf("%s:%d ", inet_ntoa(ip->ip_dst), dport);
        printf("%d %d\n",ip->ip_p, udp->uh_len);

        break;
    }

    default:
    {
        printf("%d ",ip->ip_p);
        printf("other protocals.\n");
        break;
    }
    }
}

int write(const u_char *p, int len )
{
    FILE *fp;
    fp = fopen("/opt/mm/bin","a");
    fwrite(p, len, 1, fp );
    fwrite("\n\n", 4, 1, fp );
    return fclose(fp);
}

double time_diff(struct timeval x , struct timeval y);

void test()
{
    pcap_t *handle; /* 会话句柄 */
    char *dev; /* 执行嗅探的设备 */
    char errbuf[PCAP_ERRBUF_SIZE]; /* 存储错误信息的字符串 */
    struct bpf_program filter; /* 已经编译好的过滤器 */
    char filter_app[] = "port 80"; /* 过滤表达式 */
    bpf_u_int32 mask; /* 所在网络的掩码 */
    bpf_u_int32 net; /* 主机的IP地址 */
    //struct pcap_pkthdr header; /* 由pcap.h定义 */
    //const u_char *packet; /* 实际的包 */
    /* Define the device */
    /* dev = pcap_lookupdev(errbuf); */
    dev = "em2";  /* 网卡名称 */
    pcap_lookupnet(dev, &net, &mask, errbuf); /* 探查设备属性 */
    handle = pcap_open_live(dev, 65536, 1, 0, errbuf); /* 以混杂模式打开会话 */
    pcap_compile(handle, &filter, filter_app, 0, net); /* 编译并应用过滤器 */
    pcap_setfilter(handle, &filter);

    pcap_loop( handle, 10, loop_callback, NULL);
    pcap_close(handle); /* 关闭会话 */
    return ;
}

int standord_test(int argc, char **argv)
{

    unsigned int pkt_counter=0;   // packet counter
    unsigned long byte_counter=0; //total bytes seen in entire trace
    unsigned long cur_counter=0; //counter for current 1-second interval
    unsigned long max_volume = 0;  //max value of bytes in one-second interval
    //unsigned long current_ts=0; //current timestamp
    //unsigned long previous_ts=0;  //previous timestamp

    struct timeval cur_ts = {0,0};  //current timestamp
    struct timeval pre_ts =  {0,0};  //previous timestamp

    // time_t nowtime;
    // struct tm *nowtm;
    // char tmbuf[64], buf[64];
    //temporary packet buffers

    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // The actual packet

    //check command line arguments
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]);
        exit(1);

    }

    //-------- Begin Main Packet Processing Loop -------------------
    //loop through each pcap file in command line args
    for (int fnum=1; fnum < argc; fnum++)
    {

        //-----------------
        //open the pcap file
        pcap_t *handle;
        char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
        handle = pcap_open_offline(argv[fnum], errbuf);   //call pcap library function

        if (handle == NULL)
        {
            fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[fnum], errbuf);
            return(2);
        }

        //-----------------
        //begin processing the packets in this particular file, one at a time

        while (packet = pcap_next(handle,&header))
        {
            // header contains information about the packet (e.g. timestamp)

            // printf("Grabbed packet of length %d\n",header.len);
            // printf("Recieved at ..... %.6lf\n",(double)header.ts.tv_usec);
            // //printf("Recieved at ..... %s\n",ctime((const time_t*)&header.ts.tv_usec));
            // printf("Ethernet address length is %d\n",ETHER_HDR_LEN);
            // nowtime = header.ts.tv_sec;
            // nowtm = localtime(&nowtime);
            //strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
            // tmbuf[0]='0';
            // tmbuf[1]='\0';
            // snprintf(buf, sizeof buf, "%s.%06d", tmbuf, header.ts.tv_usec);
            //printf("%s\n",buf );

            u_char *pkt_ptr = (u_char *)packet; //cast a pointer to the packet data

            //parse the first (ethernet) header, grabbing the type field
            int ether_type = ((int)(pkt_ptr[12]) << 8) | (int)pkt_ptr[13];
            int ether_offset = 0;

            if (ether_type == ETHER_TYPE_IP) //most common
                ether_offset = 14;
            else if (ether_type == ETHER_TYPE_8021Q) //my traces have this
                ether_offset = 18;
            else
                fprintf(stderr, "Unknown ethernet type, %04X, skipping...\n", ether_type);

            //parse the IP header
            pkt_ptr += ether_offset;  //skip past the Ethernet II header
            struct ip *ip_hdr = (struct ip *)pkt_ptr; //point to an IP header structure

            int packet_length = ntohs(ip_hdr->ip_len);

            //check to see if the next second has started, for statistics purposes
            if (cur_ts.tv_sec == 0)    //this takes care of the very first packet seen
            {
                printf("%.6lf\n", time_diff(pre_ts,cur_ts));
                pre_ts = cur_ts;
                cur_ts = header.ts;
                // } else if (header.ts.tv_sec > cur_ts.tv_sec) {
                //    //printf("%d KBps\n", cur_counter/1000); //print
                //    cur_counter = 0; //reset counters
                //    pre_ts = cur_ts;
                //    cur_ts = header.ts;   //update time interval
                //    //current_ts = header.ts.tv_sec; //update time interval
            }
            else
            {
                pre_ts = cur_ts;
                cur_ts = header.ts;   //update time interval
                printf("%.6lf\n", time_diff(pre_ts,cur_ts));
            }

            cur_counter += packet_length;
            byte_counter += packet_length; //byte counter update
            pkt_counter++; //increment number of packets seen


        } //end internal loop for reading packets (all in one file)

        pcap_close(handle);  //close the pcap file


    } //end for loop through each command line argument

    //---------- Done with Main Packet Processing Loop --------------

    //output some statistics about the whole trace
    byte_counter /= 1e6;  //convert to MB to make easier to read

    printf("Processed %d packets and %u MBytes, in %d files\n", pkt_counter, byte_counter, argc-1);
    return 0;
}
//-------------------------------------------------------------------
int main(int argc, char **argv)
{
    struct pcap_pkthdr header; // The header that pcap gives us
    const u_char *packet; // The actual packet

    //open the pcap file
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE]; //not sure what to do with this, oh well
    //check command line arguments
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]);
        exit(1);
    }
    handle = pcap_open_offline(argv[1], errbuf);   //call pcap library function
    if (handle == NULL)
    {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
        return(2);
    }
    pcap_loop( handle, 5, loop_callback, NULL);
    pcap_close(handle);  //close the pcap file
    return 0; //done
} //end of main() function

double time_diff(struct timeval x , struct timeval y)
{
    double x_ms , y_ms , diff;

    x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
// printf("before : %.6lf s\n" , x_ms/1000000 );
    y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
    //printf("after : %.6lf s\n" , y_ms/1000000 );
    diff = (double)y_ms - (double)x_ms;

    return diff/1000000;
}
