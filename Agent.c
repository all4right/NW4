//
// Packet Capture Example: Onlie packet capture
//
// Network Software Design
// Department of Software and Computer Engineering, Ajou University
// by Byeong-hee Roh
//
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <pcap/pcap.h>
#include <winsock.h>
#include <stdio.h>
#include <stdlib.h>

#pragma warning(disable:4996)

#define BUFSIZE 1500

#define LINE_LEN 16

 // litereals realted to distinguishing protocols
#define ETHERTYPE_IP		0x0800
#define ETH_II_HSIZE		14		// frame size of ethernet v2
#define ETH_802_HSIZE		22		// frame size of IEEE 802.3 ethernet
#define IP_PROTO_IP		    0		// IP
#define IP_PROTO_TCP		6		// TCP
#define IP_PROTO_UDP		17		// UDP
#define	RTPHDR_LEN			12		// Length of basic RTP header
#define CSRCID_LEN			4		// CSRC ID length
#define	EXTHDR_LEN			4		// Extension header length

unsigned long	net_ip_count;
unsigned long	net_etc_count;
unsigned long	trans_tcp_count;
unsigned long	trans_udp_count;
unsigned long	trans_etc_count;

#define SNAPLEN 68        // size of captured packet
#define MAX_CAP_PKT  5000    // max. number of stored pkts

// Macros
// pntohs : to convert network-aligned 16bit word to host-aligned one
#define pntoh16(p)  ((unsigned short)                       \
                    ((unsigned short)*((unsigned char *)(p)+0)<<8|  \
                     (unsigned short)*((unsigned char *)(p)+1)<<0))

// pntohl : to convert network-aligned 32bit word to host-aligned one
#define pntoh32(p)  ((unsigned short)*((unsigned char *)(p)+0)<<24|  \
                    (unsigned short)*((unsigned char *)(p)+1)<<16|  \
                    (unsigned short)*((unsigned char *)(p)+2)<<8|   \
                    (unsigned short)*((unsigned char *)(p)+3)<<0)

char*   iptos(u_long in);

// call back function
void    get_stat(u_char* user, const struct pcap_pkthdr* h, const u_char* p);

int	    numpkt_per_sec, numbyte_per_sec;	// packet and byte rates per second
int	    tot_capured_pk_num = 0;		        // total number of captured packets
long	crnt_sec, prev_sec;		            // time references in second
pcap_t* adhandle;                           // globally defined for callback fucntion

// 소켓 함수 오류 출력 후 종료
void err_quit(char *msg)
{
	printf("Error [%s] ... program terminated \n",msg);
	exit(-1);
}

// 소켓 함수 오류 출력
void err_display(char *msg)
{
	printf("socket function error [%s]\n", msg);
}

int main()
{
    // 데이터 통신에 사용할 변수
	SOCKET listen_sock;
	SOCKET client_sock;
	SOCKADDR_IN serveraddr;
	SOCKADDR_IN clientaddr;
	int		addrlen;
	char	buf[BUFSIZE+1];
	int		retval, msglen;

    //for packet capture
    
    pcap_t*             adhandle;
    pcap_if_t*          alldevs;
    pcap_if_t*          d;

    char                errbuf[PCAP_ERRBUF_SIZE];
    struct pcap_pkthdr* pkt_hdr;    // captured packet header
    const u_char*       pkt_data;   // caputred packet data
    time_t              local_tv_sec;
    struct tm*          ltime;
    char                timestr[16];

    int		i, ret;			// for general use
    int		ndNum = 0;	// number of network devices
    int		devNum;		// device Id used for online packet capture

	// 윈속 초기화
	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2,2), &wsa) != 0)
		return -1;

	// socket()
	listen_sock = socket(AF_INET, SOCK_STREAM, 0);
	if(listen_sock == INVALID_SOCKET) err_quit("socket()");	
	
	// server address
	ZeroMemory(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(9000);
	serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

	// bind()
	retval = bind(listen_sock, (SOCKADDR *)&serveraddr, sizeof(serveraddr));
	if(retval == SOCKET_ERROR) err_quit("bind()");
	
	// listen()
	retval = listen(listen_sock, SOMAXCONN);
	if(retval == SOCKET_ERROR) err_quit("listen()");


	while(1){
		// accept()
		addrlen = sizeof(clientaddr);
		client_sock = accept(listen_sock, (SOCKADDR *)&clientaddr, &addrlen);
		if(client_sock == INVALID_SOCKET) {
			err_display("accept()");
			continue;
		}

		printf("\n[TCP Server] Client accepted : IP addr=%s, port=%d\n", 
			inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));

		// 클라이언트와 데이터 통신
		while(1){

            //printf("default device: %s\n", pcap_lookupdev(errbuf));

            /* Retrieve the device list */
            if (pcap_findalldevs(&alldevs, errbuf) == -1)
            {
                fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
                exit(1);
            }

            /* Print the list */
            printf("\n");
            pcap_addr_t* a;
            for (d = alldevs; d; d = d->next)
            {
                // device name
                printf(" [%d] %s", ++ndNum, d->name);

                // description
                if (d->description)
                    printf(" (%s) ", d->description);

                // loopback address
                // printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

                // IP addresses
                for (a = d->addresses; a; a = a->next) {
                    if (a->addr->sa_family == AF_INET) {
                        if (a->addr)
                            printf("[%s]", iptos(((struct sockaddr_in*)a->addr)->sin_addr.s_addr));
                        //if (a->netmask)
                        //    printf("\tNetmask: %s\n", iptos(((struct sockaddr_in*)a->netmask)->sin_addr.s_addr));
                        //if (a->broadaddr)
                        //    printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in*)a->broadaddr)->sin_addr.s_addr));
                        //if (a->dstaddr)
                        //    printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in*)a->dstaddr)->sin_addr.s_addr));
                        break;
                    }
                }
                printf(" flag=%d\n", (int)d->flags);
            }
            printf("\n");
            /* error ? */
            if (ndNum == 0)
            {
                printf("\nNo interfaces found! Make sure Npcap is installed.\n");
                return -1;
            }

            /* select device for online packet capture application */
            printf(" Enter the interface number (1-%d):", ndNum);
            scanf("%d", &devNum);

            /* select error ? */
            if (devNum < 1 || devNum > ndNum)
            {
                printf("\nInterface number out of range.\n");
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
            }

            /* Jump to the selected adapter */
            for (d = alldevs, i = 0; i < devNum - 1; d = d->next, i++);

            /* Open the adapter */
            if ((adhandle = pcap_open_live( d->name, // name of the device
                                            65536,     // portion of the packet to capture. 
                                                        // 65536 grants that the whole packet will be captured on all the MACs.
                                            1,         // promiscuous mode
                                            1000,      // read timeout
                                            errbuf)     // error buffer
                ) == NULL)
            {
                fprintf(stderr, "\nUnable to open the adapter. %s is not supported by Npcap\n", d->name);
                /* Free the device list */
                pcap_freealldevs(alldevs);
                return -1;
            }

            printf("\n Selected device %s is available\n\n", d->description);
            pcap_freealldevs(alldevs);

            // start the capture
            numpkt_per_sec = numbyte_per_sec = net_ip_count = trans_tcp_count = trans_udp_count = 0;

            pcap_loop(adhandle, 	// capture device handler
                        -1, 	   	// forever
                        get_stat,   // callback function
                        NULL);      // no arguments


            /* Close the handle */
            pcap_close(adhandle);

            /* At this point, we don't need any more the device list. Free it */

			/*TODO 
            request 받고 response 송신설정
            */

			if(retval == SOCKET_ERROR){
				err_display("send()");
				break;
			}
		}

		// closesocket()
		closesocket(client_sock);
		printf("[TCP 서버] 클라이언트 종료: IP 주소=%s, 포트 번호=%d\n", 
			inet_ntoa(clientaddr.sin_addr), ntohs(clientaddr.sin_port));
	}

	// closesocket()
	closesocket(listen_sock);

	// 윈속 종료
	WSACleanup();

    return 0;
}

/* From tcptraceroute, convert a numeric IP address to a string : source Npcap SDK */
#define IPTOSBUFFERS	12
char* iptos(u_long in)
{
    static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
    static short which;
    u_char* p;

    p = (u_char*)&in;
    which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
    sprintf(output[which], "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
    return output[which];
}

void get_stat(u_char* user, const struct pcap_pkthdr* h,    const u_char* p)
{
    struct tm* ltime;
    char timestr[16];
    unsigned short type;

    // convert the timestamp to readable format
    ltime = localtime(&h->ts.tv_sec);
    strftime(timestr, sizeof timestr, "%H:%M:%S", ltime);

    // check time difference in second
    crnt_sec = h->ts.tv_sec;
    if (tot_capured_pk_num == 0) prev_sec = crnt_sec;
    if (crnt_sec > prev_sec) {
        printf("%s totpk(%6d) pkr(%3d) btr(%5d) IP(%3d) TCP(%3d) UDP(%3d)\n",
            timestr, tot_capured_pk_num, numpkt_per_sec, numbyte_per_sec, net_ip_count,
            trans_tcp_count, trans_udp_count);
        numpkt_per_sec = numbyte_per_sec = net_ip_count = trans_tcp_count = trans_udp_count=0;
    }
    prev_sec = crnt_sec;
    numpkt_per_sec++;
    numbyte_per_sec += h->len;
    if ((type = pntoh16(&p[12])) == 0x0800) {
        net_ip_count++;
        if (p[23] == IP_PROTO_UDP)
            trans_udp_count++;
        else if (p[23] == IP_PROTO_TCP)
            trans_tcp_count++;
        else
            trans_etc_count++;
    }

    if (tot_capured_pk_num++ > MAX_CAP_PKT) {
        printf("\n\n %d-packets were captured ...\n", tot_capured_pk_num);

        // close all devices and files
        pcap_close(adhandle);
        exit(0);
    }
}