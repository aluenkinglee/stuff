#ifndef MACRO_H
#define MACRO_H

#ifndef IP_MACRO
#define IP_RF 0x8000              	//  reserved fragment flag
#define IP_DF 0x4000              	//  dont fragment flag
#define IP_MF 0x2000              	//  more fragments flag
#define IP_OFFMASK 0x1fff		//  mask for fragmenting bits
#endif

#ifndef TCP_MACRO
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
#endif

#ifndef ETHER
#define SNAP_LEN 1518       // 以太网帧最大长度
#define SIZE_ETHERNET 14   // 以太网包头长度 mac: 6*2 + type: 2 = 14
#endif

#ifndef ETHER_ADDR_LEN
#define ETHER_ADDR_LEN  6  // mac地址长度
#endif

// defines for the packet type code in an ETHERNET header
#define ETHER_TYPE_IP (0x0800)
#define ETHER_TYPE_8021Q (0x8100)

#endif