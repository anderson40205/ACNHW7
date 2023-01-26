#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <pcap/pcap.h>
#include <sys/time.h>
#include <assert.h>
#include <pthread.h>
#include <errno.h>
#include "fill_packet.h"
//pid_t pid;
//two structure for send and received argument
struct arg_recv
{
    int id;
    int sequence;
	struct timeval *start_time;
	struct timeval *end_time;
	char toSendIP[16];
	int inputTimeout;
};
struct arg_send
{
	int sockfd;
	myicmp *packet;
	struct sockaddr_in dst;
};
int get_local_ip(const char *eth_inf, char *ip)
{
    int sd;
    struct sockaddr_in sin;
    struct ifreq ifr;
 
    sd = socket(AF_INET, SOCK_DGRAM, 0);
    if (-1 == sd)
    {
        printf("socket error: %s\n", strerror(errno));
        return -1;
    }
    strncpy(ifr.ifr_name, eth_inf, IFNAMSIZ);
    ifr.ifr_name[IFNAMSIZ - 1] = 0; 
    // if error: No such device
    if (ioctl(sd, SIOCGIFADDR, &ifr) < 0)
    {
        printf("ioctl error: %s\n", strerror(errno));
        close(sd);
        return -1;
    } 
    memcpy(&sin, &ifr.ifr_addr, sizeof(sin));
    snprintf(ip, 16, "%s", inet_ntoa(sin.sin_addr));
 
    close(sd);
    return 0;
}
char *getIPandMASK(char* NIC , uint8_t flag)
{	
	int ret;
	char errbuf[PCAP_ERRBUF_SIZE];
	bpf_u_int32 netp;
	bpf_u_int32 maskp;
	struct in_addr addr1;
	struct in_addr addr2;
	struct bpf_program fcode;
	char *net;
	char *mask;
	ret = pcap_lookupnet(NIC, &netp, &maskp, errbuf);
	//可以獲取指定設備的ip地址，子網掩碼等信息
	//netp：傳出參數，指定網絡接口的ip(network id)地址
	//maskp：傳出參數，指定網絡接口的子網掩碼
	//pcap_lookupnet()失敗返回-1
	if(ret == -1)
	{
		fprintf(stderr,"%s\n",errbuf);
		exit(1);
	}
	if(flag==1) goto MASK;
	addr1.s_addr = netp;
	net = inet_ntoa(addr1);
	if(net == NULL){
		perror("inet_ntoa");
		exit(1);
	}
	return net;
MASK:	
	addr2.s_addr = maskp;
	mask = inet_ntoa(addr2);
	if(mask == NULL)
	{
		perror("inet_ntoa");
		exit(1);
	}
	return mask;
}
int time_passed(int packets_received, struct timeval *current_time, struct timeval *end_time, int nqueries) 
{
    if (packets_received >= nqueries || timercmp(current_time, end_time, >)){ return 1;}
    return 0;
}
void *sendMessage(void *ptr)
{
	struct arg_send *args = ptr;
	sleep(1);//避免send thread搶快導致recv那邊的thread還沒開起來
	//printf("sendMessage\n");
	// printf("sendMessage: sockfd = %d\n",args->sockfd);
	
    if(sendto(args->sockfd, args->packet, PACKET_SIZE, 0, (struct sockaddr *)&args->dst, sizeof(args->dst)) < 0)
	{
		perror("sendto");
		exit(1);
	}
}
void *recvMessage(void* data) 
{
	//printf("recvMessage\n");
	struct arg_recv *args = data;
	// printf("pid = %d\n",args->arg1);
	// printf("sequence = %d\n",args->arg2);
	//printf("toSendIP = %s\n",args->toSendIP);
	struct timeval deltas[1];
	struct timeval current_time;
	struct timeval test_time;
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) 
	{
		perror("socket error"); 
		exit(EXIT_FAILURE);
    }
	gettimeofday(&current_time, NULL);
	while(!time_passed(0, &current_time, args->end_time, 1))
	{
		struct sockaddr_in sender;
		socklen_t sender_len = sizeof(sender);
		uint8_t buffer[IP_MAXPACKET];
		//防超時設計 (select fd_set...)
		//printf("args->inputTimeout = %d\n",args->inputTimeout);
		struct timeval timeout = { 0, args->inputTimeout*1000 };//乘1000，因為這個結構接µs，但輸入是ms
		fd_set in_set;
		FD_ZERO(&in_set);
		FD_SET(sockfd, &in_set);
		// select the set
		int cnt = select(sockfd + 1, &in_set, NULL, NULL, &timeout);

		if (FD_ISSET(sockfd, &in_set))
		{
			//printf("pre recvfrom\n");
			int packet_len = recvfrom(sockfd, buffer, IP_MAXPACKET, 0, (struct sockaddr *)&sender, &sender_len);
			//printf("post recvfrom\n");
			
			if (packet_len < 0) {perror("recvfrom error"); exit(EXIT_FAILURE);}
			char sender_ip_str[20];
			const char *inet_ntop_ret = inet_ntop(AF_INET, &(sender.sin_addr), sender_ip_str, sizeof(sender_ip_str));
			assert(inet_ntop_ret != NULL);//IP為NULL的話，中止
			
			
			gettimeofday(&test_time, NULL);//
			//printf("test_time %.1f ms ", test_time.tv_usec/1000.0);
			
			struct iphdr *ip_header = (struct iphdr *)buffer;
			int ip_header_len = 4 * ip_header->ihl;
			// 取出 ICMP Header
			struct icmphdr *icmp_ptr = (struct icmphdr *)(buffer + ip_header_len);
			uint8_t icmp_type = icmp_ptr->type;
			// printf("icmp_ptr->type = %d\n",icmp_ptr->type);
			// printf("checksum = %x\n",icmp_ptr->checksum);
			// printf("icmp_ptr->un.echo.sequence = %d\n",htons(icmp_ptr->un.echo.sequence));
			// printf("args->arg2 = %d\n",args->arg2);
			// printf("icmp_ptr->un.echo.id = %d\n",icmp_ptr->un.echo.id);
			// printf("args->arg1 = %d\n",args->arg1);
			int t = 0;
			// for(t=28;t<=37;t++)
				// printf("%x\n",buffer[t]);//ICMP reply
			// printf("\n");
			
			// printf("icmp_ptr->type is %d\n",icmp_ptr->type);
			if(htons(icmp_ptr->un.echo.sequence) == args->sequence && icmp_ptr->un.echo.id == args->id && strcmp(args->toSendIP,sender_ip_str)==0  
			&& (buffer[28]==0x4d &&buffer[29]==0x31 &&buffer[30]==0x31 &&buffer[31]==0x33 &&buffer[32]==0x30 && 
			buffer[33]==0x34 &&buffer[34]==0x30 &&buffer[35]==0x30 &&buffer[36]==0x33 &&buffer[37]==0x33))
			{
				if(icmp_ptr->type==0)
				{
					//printf("startTime.tv_sec = %lf , endTime.tv_sec = %lf\n",args->start_time->tv_sec/1000.0 , args->end_time->tv_sec/1000.0);
					gettimeofday(&current_time, NULL);//收到封包的結束時間
					//printf("current_time %.1f ms ", current_time.tv_usec/1000.0);
					timersub(&current_time, args->start_time, &deltas[0]);//算發送到接收過了多久
					printf("\tReply from : %s , time : %lf ms\n",sender_ip_str, deltas[0].tv_usec/1000.0);
					//printf("startTime.tv_sec = %lf , endTime.tv_sec = %lf\n",args->start_time->tv_sec/1000.0 , args->end_time->tv_sec/1000.0);
					break;
				}
			}
			else if(icmp_ptr->type==3 && (buffer[56]==0x4d &&buffer[57]==0x31 &&buffer[58]==0x31 &&buffer[59]==0x33 &&buffer[60]==0x30 && 
			buffer[61]==0x34 &&buffer[62]==0x30 &&buffer[63]==0x30 &&buffer[64]==0x33 &&buffer[65]==0x33))
			{
				printf("\tDestination unreachable\n");
				// for(t=56;t<=65;t++)
					// printf("%x\n",buffer[t]);//unreachable and time out
				break;
			}
			else if(icmp_ptr->type==11 && (buffer[56]==0x4d &&buffer[57]==0x31 &&buffer[58]==0x31 &&buffer[59]==0x33 &&buffer[60]==0x30 && 
			buffer[61]==0x34 &&buffer[62]==0x30 &&buffer[63]==0x30 &&buffer[64]==0x33 &&buffer[65]==0x33))
			{
				printf("\tTime-to-live exceeded\n");
				// for(t=56;t<=65;t++)
					// printf("%x\n",buffer[t]);//unreachable and time out
				break;
			}
		}
		else
		{
			// nothing received from client in last 8 seconds
			printf("\tNothing received from client in last %d ms\n",args->inputTimeout);
			break;       
		}
		//
	}
	close(sockfd);
	//pthread_exit(NULL); // 離開子執行緒
}
char* increment_address(const char* address_string)
{
    // convert the input IP address to an integer
    in_addr_t address = inet_addr(address_string);

    // add one to the value (making sure to get the correct byte orders)
    address = ntohl(address);
    address += 1;
    address = htonl(address);

    // pack the address into the struct inet_ntoa expects
    struct in_addr address_struct;
    address_struct.s_addr = address;

    // convert back to a string
    return inet_ntoa(address_struct);
}
int main(int argc, char* argv[])
{
	char* net;
	int timeout = DEFAULT_TIMEOUT;
	char *inputNIC;
	char* mask;
	if(strncmp("-i", argv[1], 2) == 0)
	{
		inputNIC = (char*)malloc(strlen(argv[2]));
		strcpy(inputNIC,argv[2]);
	}
	//printf("inputNIC=%s\n",inputNIC);
	if(strncmp("-t", argv[3], 2) == 0)
	{
		timeout = atoi(argv[4]);
		//printf("timeout=%d\n",timeout);
	}
	char srcIP[16];
	get_local_ip(inputNIC, srcIP);
	//printf("ori srcIP = %s\n",srcIP);
	mask = (char*)malloc(strlen(getIPandMASK(inputNIC,1)));
	strcpy(mask,getIPandMASK(inputNIC,1));
	net = (char*)malloc(strlen(getIPandMASK(inputNIC,0)));
	strcpy(net,getIPandMASK(inputNIC,0));
	//strcpy(srcIP,"140.117.169.3");
	//net="140.117.169.1";
	//net="140.117.169.39";
	//printf("str comp %d\n",strcmp(srcIP, "10.0.2.15"));
	int scani;
	int sequence = 1;
	int scanRange;
	//mask = "255.255.0.0";
	if(strcmp(mask,"255.255.255.0")==0)scanRange=256;//0~255
	else if(strcmp(mask,"255.255.0.0")==0)scanRange=512;//0~255 0~255
	else if(strcmp(mask,"255.0.0.0")==0)scanRange=768;
	for(scani=0;scani<=scanRange;scani++)
	{
		int ii,arr[4];
		char tempNet[16];
		strcpy(tempNet,net);
		char *ipPointer = strtok(tempNet,".");
		for(ii=0;ii<4;ii++)
		{
			if(ipPointer == NULL)
			{
				arr[ii]=0;
				break;
			}
			else
			{
				arr[ii] = atoi(ipPointer);
				//printf("%d\n",arr[ii]);
			}
			ipPointer = strtok(NULL,".");
		}
		
		if(strcmp(srcIP, net)==0 || arr[3]==0 || arr[3]==255) goto INCREASEIP;//自己的IP不用掃 .0 跟 .255也不用掃
		pthread_t sendT;
		pthread_t recvT;
		int sockfd;
		int on = 1;
		
		uint16_t pid = getpid();//定義的struct用u_int16_t
		struct timeval startTime, endTime;
		struct sockaddr_in dst;
		myicmp *packet = (myicmp*)malloc(PACKET_SIZE);
		memset(packet, 0, sizeof(*packet));
		
		strcpy(packet->data,"M113040033");//填資料
		if((sockfd = socket(AF_INET, SOCK_RAW , IPPROTO_RAW)) < 0)
		{
			perror("socket");
			exit(1);
		}
		//printf("main: sockfd = %d\n",sockfd);
		//選項所在的協議層為IP 需要訪問的選項名IP_HDRINCL 
		if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0)
		{
			perror("setsockopt");
			exit(1);
		}
		//https://learn.microsoft.com/zh-tw/windows/win32/winsock/ipproto-ip-socket-options
		//當需要編寫自己的IP數據包首部時，可以在原始套接字上設置套接字選項IP_HDRINCL.
		//在不設置這個選項的情況下，IP協議自動填充IP數據包的首部
		// 如果沒有設置IP_HDRINCL選項時，包內可寫的內容為數據部分，內核將自動創建IP首部。
		// 如果設置了IP_HDRINCL選項，則包內要填充的內容為IP數據包和首部。內核只負責填充下面兩個域：
		// 如果將IP數據包的標識域設置為0，內核將設置這個域。內核總是計算和填充IP數據包首部的校驗和
		//net="192.168.56.101";
		
		fill_iphdr(&packet->ip_hdr, net,inputNIC);
		fill_icmphdr(&packet->icmp_hdr, pid, &sequence, packet->data);

		// 當設定on為 TRUE時，表示應用程式會提供 IP 標頭。 僅適用于SOCK_RAW通訊端。 
		// 如果應用程式提供的值為零，TCP/IP 服務提供者可能會設定識別碼欄位。 
		// IP_HDRINCL選項只會套用至通訊協定SOCK_RAW類型。 支援SOCK_RAW的 TCP/IP 服務提供者也應該支援IP_HDRINCL。
		/*
		 *   Use "sendto" to send packets, and use "pcap_get_reply"(in pcap.c) 
			 or use the standard socket like the one in the ARP homework
		 *   to get the "ICMP echo response" packets 
		 *	 You should reset the timer every time before you send a packet.
		*/
		memset(&dst, 0, sizeof(dst));
		dst.sin_family = AF_INET;
		//printf("net = %s\n",net);
		int inet_pton_ret = inet_pton(AF_INET, net, &dst.sin_addr);
		assert(inet_pton_ret == 1);//inet_pton有問題導致出來的結果不是1的話，中止
		
		struct arg_recv ar;
		ar.id = pid;
		ar.sequence = sequence;
		ar.start_time = &startTime;
		ar.end_time = &endTime;
		strcpy(ar.toSendIP,net);
		ar.inputTimeout = timeout;
		//先wait
		pthread_create(&recvT, NULL, recvMessage, (void *)&ar); // 建立子執行緒
		// int sockfd;
		// myicmp *packet;
		// struct sockaddr_in dst;
		struct arg_send as;
		as.sockfd = sockfd;
		as.packet = packet;
		as.dst = dst;
		pthread_create(&sendT, NULL, sendMessage, (void *)&as); // 建立子執行緒
		printf("PING %s (data size = 10, id = 0x%04x, seq = %d , timeout = %d ms)\n",net,pid,sequence,timeout);
		//printf("startTime.tv_sec = %lf , endTime.tv_sec = %lf\n",startTime.tv_sec/1000.0 , endTime.tv_sec/1000.0);
		gettimeofday(&startTime, NULL);
		endTime = startTime;
		endTime.tv_sec++;
		//printf("startTime.tv_sec = %lf , endTime.tv_sec = %lf\n",startTime.tv_sec/1000.0 ,endTime.tv_sec/1000.0);
		pthread_join(recvT,NULL);
		pthread_join(sendT,NULL); 
		sequence++;
		free(packet);
		close(sockfd);
INCREASEIP:		
		net = increment_address(net);		
	}
	return 0;
}