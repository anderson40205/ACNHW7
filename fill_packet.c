#include "fill_packet.h"
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <netpacket/packet.h>
#include <net/ethernet.h>
#include <unistd.h> //Because implicit declaration of function 'geteuid()'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <stdbool.h> //For bool type
#include <net/if.h>           // struct ifreq
#include <errno.h>
#include <ctype.h>
#include <netinet/in.h>
#include <assert.h>
#define ETH_HDRLEN 14  // Ethernet header length
#define IP4_HDRLEN 20  // IPv4 header length
#define ICMP_HDRLEN 8  // ICMP header length for echo request, excludes data
struct sockaddr_in sinn;

unsigned short csum (unsigned short *buf, int nwords)
{
	/* this function generates header checksums */
	unsigned long sum;
	for (sum = 0; nwords > 0; nwords--)
		sum += *buf++;
	sum = (sum >> 16) + (sum & 0xffff);
	sum += (sum >> 16);
	return ~sum;
}
void fill_iphdr(struct ip *ip_hdr, const char* dst_ip, char* NIC)
{
	memset(ip_hdr, 0, sizeof(*ip_hdr));
	//ip_hdr->ip_hl = IP4_HDRLEN / sizeof (uint32_t);//IP header length
	ip_hdr->ip_hl = sizeof(struct ip) >> 2;//IP header length
	ip_hdr->ip_v = 4;//IPv4
	ip_hdr->ip_tos = 0;
	ip_hdr->ip_len = PACKET_SIZE;
	ip_hdr->ip_id = htons(0);//作業指定
	ip_hdr->ip_off = htons(IP_DF);//作業指定(linux這樣寫，BSD直接=IP_DF)
	ip_hdr->ip_ttl = 1;//作業指定
	ip_hdr->ip_p = IPPROTO_ICMP;//作業指定
	//ip_hdr->ip_sum = 0xffff;//查了老半天不知道要怎麼算，先清0
	//printf("NIC: %s\n", NIC);
	ip_hdr->ip_src = sinn.sin_addr;
	//printf("local IP: %s\n", inet_ntoa(sinn.sin_addr));
	
	//如果正確執行將返回一個無符號長整數型數。如果傳入的字符串不是一個合法的IP地址，將返回INADDR_NONE;
	ip_hdr->ip_dst.s_addr = inet_addr(dst_ip);
	//printf("dst IP: %s\n", dst_ip);
}

void fill_icmphdr(struct icmphdr *icmp_hdr, uint16_t id, int *sequence, char *data)
{
	char checksumBuffer[18] = {0};
	//填ICMP封包，跟traceroute一樣
	memset(icmp_hdr, 0, sizeof(icmp_hdr));
    icmp_hdr->type = ICMP_ECHO;//8
    icmp_hdr->code = 0;
    icmp_hdr->un.echo.id = id;//作業要求，process id傳進來
	//printf("pid=%d\n",id);
    icmp_hdr->un.echo.sequence = htons((u_int16_t)*sequence);
	icmp_hdr->checksum = 0;
	icmp_hdr->checksum = computeIcmpChecksum((uint16_t *)icmp_hdr, sizeof(*icmp_hdr), data);
	//printf("icmp_hdr size = %ld\n",sizeof(icmp_hdr));
}

uint16_t computeIcmpChecksum(const void *buff, int length, char *data) 
{
    uint32_t sum;
    const uint16_t *ptr = buff;
    assert (length % 2 == 0);
    for (sum = 0; length > 0; length -= 2)
	{
		//length=8
		//printf("*ptr=%x\n",*ptr);
		sum += *ptr++;//type+code+pid+sequence(hop、ttl)
	}
	//checksum 加 data，會這樣寫是因為data長度固定的，下面都是看wireshark測出來的
	sum+=(data[0]);
	sum+=(data[1]<<8);
	sum+=(data[2]);sum+=(data[3]<<8);sum+=(data[4]);sum+=(data[5]<<8);sum+=(data[6]);sum+=(data[7]<<8);
	sum+=(data[8]);sum+=(data[9]<<8);
    sum = (sum >> 16) + (sum & 0xffff);
    return (uint16_t)(~(sum + (sum >> 16)));//~(sum += (sum >> 16));
}