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
#include <string>
#include <vector>
#include <iostream>
#include <ostream>
#include <fstream>
#include <algorithm>

#include "macro.h"
#include "dissector.h"
#include "Packet.h"

using namespace std;
typedef class Packet
{
private:
    struct pcap_pkthdr header;
    u_char *packet;
public:
    Packet(const Packet &packet)
    {
        //这里写错了。。。memcpy(&h, &packet.p, sizeof(struct pcap_pkthdr));
        memcpy(&(this->header), &packet.header, sizeof(struct pcap_pkthdr));
        this->packet = new u_char[this->header.len];
        memcpy(this->packet, packet.packet, this->header.len);
    }

    Packet& operator=(const Packet& packet)
    {
        memcpy(&(this->header), &packet.header, sizeof(struct pcap_pkthdr));
        this->packet = new u_char[packet.header.len];
        memcpy(this->packet, packet.packet, this->header.len);
        return *this;
    }

    Packet( const struct pcap_pkthdr *header, const u_char* packet)
    {
        //!!!!!!!!new u_char[len] not new u_char(len)
        this->packet = new u_char[header->len];
        memcpy(this->packet, packet, header->len);
        memcpy(&(this->header), header, sizeof(struct pcap_pkthdr));
    }
    ~Packet()
    {
        delete[] this->packet;
    }
public:
    pcap_pkthdr& get_header()
    {
        return this->header;
    }
    u_char* get_packet()
    {
        return this->packet;
    }
    Packet_ip IP()
    {
        Packet_ip ip(this->packet);
        return ip;
    }
    Packet_tcp TCP()
    {
        Packet_tcp tcp(&(this->header), this->packet);
        return tcp;
    }
} Packet;

vector<Packet> stream;

class flow
{
private:
    typedef pair<string, int> address;
    address source;
    address dest;
    vector<Packet> stream;
public:
    typedef vector<Packet>::iterator iterator;
    flow() {}
    flow(string ip_src, int sport,
         string ip_dest, int dport)
    {
        source = make_pair(ip_src, sport);
        dest = make_pair(ip_dest, dport);
    }
    flow(const flow& other)
    {
        source = other.source;
        dest = other.dest;
        stream = other.stream;
    }
    flow& operator=(const flow & other)
    {
        source = other.source;
        dest = other.dest;
        stream = other.stream;
        return *this;
    }
    ~flow() {}
public:
    size_t size()
    {
        return stream.size();
    }
    void push_back(const Packet& p)
    {
        stream.push_back(p);
    }
    void setflow(string ip_src, int sport,
                 string ip_dest, int dport)
    {
        source = make_pair(ip_src, sport);
        dest = make_pair(ip_dest, dport);
    }
    bool operator==(const flow& other) const
    {
        if ((source == other.source && dest == other.dest) ||
                (source == other.dest && dest == other.source))
            return true;
        else
            return false;
    }
    iterator begin()
    {
        return stream.begin();
    }
    iterator end()
    {
        return stream.end();
    }
};

class Flows
{
private:
    vector<flow> data;
public:
    typedef vector<flow>::iterator iterator;
    typedef Flows& ref;

    Flows() {}
    Flows(const ref other)
    {
        data = other.data;
    }
    ref operator=(const ref other)
    {
        data = other.data;
        return *this;
    }
    ~Flows()
    {
        data.clear();
    }
public:
    bool is_unique(const flow& f )
    {
        iterator iter;
        for(iter = data.begin(); iter != data.end();
                ++iter)
        {
            if (*iter == f)
                return false;
        }
        return true;
    }
    size_t size()
    {
        return data.size();
    }
    void push_back(const flow& f)
    {
        data.push_back(f);
    }
    iterator find(const flow& f)
    {
        return std::find(data.begin(), data.end(), f);
    }
    iterator erase(iterator pos)
    {
        return data.erase(pos);
    }
    std::ostream& operator<<(std::ostream& os)
    {
        os << " " ;
        return os;
    }
};

Flows flowpool;
void feature_extractor(flow f);

void loop_callback(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
    static int count = 0;                           //包计数器
    //const struct packet_ip   *ip;                 //the IP header
    const struct udp_header *udp;

    int size_ip;
    int size_tcp;


    count++;

    Packet p(header,packet);
    /* IP头 */
    Packet_ip iptest =p.IP();
    size_ip = iptest.size();

    //ip = (struct packet_ip*)(packet + SIZE_ETHERNET);

    if (size_ip < 20)
    {
        printf("无效的IP头长度: %u bytes\n", size_ip);
        return;
    }

    switch (iptest.get_protocal())
    {
    case IPPROTO_TCP:
    {
        /* TCP头 */
        Packet_tcp tcptest = p.TCP();
        size_tcp = tcptest.size();
        if (size_tcp < 20)
        {
            //printf("无效的TCP头长度: %u bytes\n", size_tcp);
            return;
        }

        flow f(iptest.source_ip(), tcptest.sport(),
               iptest.dest_ip(), tcptest.dport());

        cout << "flowpool的大小:"<<flowpool.size() << endl;
        //判断该流是否是一个心底的流？
        //说起新的流，必须还得检查它是有SYN等标志，才可以确定可以加入。
        //否则，pass 掉
        if(flowpool.is_unique(f))
        {
            //是一个新的流的开始.
            //创建流，加入到流中。
            //根据tcp中的flags判断是不是一个新的流。
            if(Dissector::is_tcp_new(p.TCP().get_flags()))
            {
                f.push_back(p);
                cout <<"目前的该流的大小："<<f.size()<<endl;
                flowpool.push_back(f);
                //开始下一个包。
            }
        }
        else
        {
            //不是一个新的流，查找在数据中的位置。
            Flows::iterator iter=flowpool.find(f);

            if((*iter).size()<10)
            {
                iter->push_back(p);
                cout <<"目前的该流的大小："<<(*iter).size()<<endl;
            }
            else
            {
                //提取大小为10的流的特征向量。
                feature_extractor(*iter);
                flowpool.erase(iter);
                //开始检查下一个流。
            }

        }
        break;
    }

    case IPPROTO_UDP:
    {
        udp = (udp_header*) (packet + SIZE_ETHERNET + size_ip);

        int sport =  ntohs(udp->uh_sport);
        int dport =  ntohs(udp->uh_dport);

        printf("%s:%d -> ", iptest.source_ip(), sport);
        printf("%s:%d ", iptest.dest_ip(), dport);
        printf("%lu %d\n",iptest.get_protocal(), udp->uh_len);

        break;
    }

    default:
    {
        printf("%lu ",iptest.get_protocal());
        printf("other protocals.\n");
        break;
    }
    }
}
template <typename T>
int write(const vector<T> &data)
{
    ofstream outfile;
    outfile.open("features.txt",ofstream::out | ofstream::app);
    //typename vector<T>::iterator iter;
    for (size_t i=0; i<data.size(); i++)
    {
        outfile << data[i] << " ";
    }
    outfile.close();
    return 0;
}

double time_diff(struct timeval x , struct timeval y);

void feature_extractor(flow f)
{
    struct pcap_pkthdr header; // The header that pcap gives us

    struct timeval cur_ts = {0,0};  //current timestamp
    struct timeval pre_ts =  {0,0};  //previous timestamp

    vector<string> timeintervals;
    vector<int> lens;
    vector<string> features;
    char buffer[50];

    flow::iterator iter;
    cout << "f size:"<<f.size()<<"...."<<endl;
    for(iter = f.begin(); iter != f.end();
            ++iter)
    {
        //计算时间间隔。
        header = iter->get_header();
        if (cur_ts.tv_sec == 0)    //this takes care of the very first packet seen
        {
            //printf("%.6lf\n", time_diff(pre_ts,cur_ts));
            pre_ts = cur_ts;
            cur_ts = header.ts;
        }
        else
        {
            pre_ts = cur_ts;
            cur_ts = header.ts;   //update time interval
            //printf("%.6lf\n", time_diff(pre_ts,cur_ts));
            sprintf(buffer,"%.6lf ", time_diff(pre_ts,cur_ts));
            cout << buffer <<" " ;
            timeintervals.push_back(buffer);
        }
        // 包的长度。
        lens.push_back(header.len);
        //计算每个报文自己的属性
        //sip,dip,sport,dport,payload_len,window size,...
        Packet p(&(iter->get_header()),iter->get_packet());
        Packet_ip ip =p.IP();
        string sip = ip.source_ip();
        string dip = ip.dest_ip();
        if(ip.get_protocal() == IPPROTO_TCP)
        {
            Packet_tcp tcp = p.TCP();
            sprintf(buffer,"%s %s %hu %hu %zu",
                    sip.c_str(),
                    dip.c_str(),
                    tcp.sport(),
                    tcp.dport(),
                    tcp.payload_length());
            features.push_back(buffer);
            cout << buffer <<endl;

        }
        else if (ip.get_protocal() == IPPROTO_UDP)
        {
            //udp
            //features.push_back(buffer);
            ;
        }

    }
    write(timeintervals);
    write(lens);
    write(features);

    //输出换行符
    fstream outfile;
    outfile.open("features.txt",ofstream::out | ofstream::app);
    outfile<<endl;
    outfile.close();
}

int run(int argc, char **argv)
{
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
    pcap_loop( handle, 30, loop_callback, NULL);
    pcap_close(handle);  //close the pcap file

    return 0; //done
} //end of main() function

int preprocess(int argc,char **argv)
{
    struct pcap_pkthdr header;
    const u_char *packet;

    const struct udp_header *udp;
    int size_ip;
    int size_tcp;

    if (argc < 2)
    {

        fprintf(stderr, "Usage: %s [input pcaps]\n", argv[0]);
        exit(1);
    }
    // Begin Main Packet Processing Loop
    // loop through each pcap file in command line args

    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    // open the pcap file
    handle = pcap_open_offline(argv[1], errbuf);

    if (handle == NULL)
    {
        fprintf(stderr,"Couldn't open pcap file %s: %s\n", argv[1], errbuf);
        return(1);
    }

    // begin processing the packets in this particular file
    // one at a time
    while (packet = pcap_next(handle,&header))
    {
        Packet p(&header,packet);
        /* IP头 */
        Packet_ip iptest =p.IP();
        size_ip = iptest.size();

        //ip = (struct packet_ip*)(packet + SIZE_ETHERNET);

        if (size_ip < 20)
        {
            printf("无效的IP头长度: %u bytes\n", size_ip);
            continue;
        }

        switch (iptest.get_protocal())
        {
        case IPPROTO_TCP:
        {
            /* TCP头 */
            Packet_tcp tcptest = p.TCP();
            size_tcp = tcptest.size();
            if (size_tcp < 20)
            {
                //printf("无效的TCP头长度: %u bytes\n", size_tcp);
                continue;
            }

            flow f(iptest.source_ip(), tcptest.sport(),
                   iptest.dest_ip(), tcptest.dport());

            cout << "flowpool的大小:"<<flowpool.size() << endl;
            //判断该流是否是一个心底的流？
            //说起新的流，必须还得检查它是有SYN等标志，才可以确定可以加入。
            //否则，pass 掉
            if(flowpool.is_unique(f))
            {
                //是一个新的流的开始.
                //创建流，加入到流中。
                //根据tcp中的flags判断是不是一个新的流。
                if(Dissector::is_tcp_new(p.TCP().get_flags()))
                {
                    f.push_back(p);
                    cout <<"目前的该流的大小："<<f.size()<<endl;
                    flowpool.push_back(f);
                    //开始下一个包。
                }
            }
            else
            {
                //不是一个新的流，查找在数据中的位置。
                Flows::iterator iter=flowpool.find(f);

                if((*iter).size()<10)
                {
                    iter->push_back(p);
                    cout <<"目前的该流的大小："<<(*iter).size()<<endl;
                }
                else
                {
                    //提取大小为10的流的特征向量。
                    feature_extractor(*iter);
                    flowpool.erase(iter);
                    //开始检查下一个流。
                }

            }
            break;
        }

        case IPPROTO_UDP:
        {
            udp = (udp_header*) (packet + SIZE_ETHERNET + size_ip);

            int sport =  ntohs(udp->uh_sport);
            int dport =  ntohs(udp->uh_dport);

            printf("%s:%d -> ", iptest.source_ip(), sport);
            printf("%s:%d ", iptest.dest_ip(), dport);
            printf("%lu %d\n",iptest.get_protocal(), udp->uh_len);

            break;
        }

        default:
        {
            printf("%lu ",iptest.get_protocal());
            printf("other protocals.\n");
            break;
        }// end of default

        }
    }
    return 1;
}
int main(int argc, char **argv)
{
    preprocess(argc, argv);
    return 0;
}
double time_diff(struct timeval x , struct timeval y)
{
    double x_ms , y_ms , diff;
    x_ms = (double)x.tv_sec*1000000 + (double)x.tv_usec;
    y_ms = (double)y.tv_sec*1000000 + (double)y.tv_usec;
    //printf("after : %.6lf s\n" , y_ms/1000000 );
    diff = (double)y_ms - (double)x_ms;
    return diff/1000000;
}
