#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#define BUFSIZE 1500

typedef struct MIB {
	int	    tot_capured_pk_num; //총 비트 수
	int	    numpkt_per_sec, numbyte_per_sec; //비트율
	unsigned long	net_ip_count;
	unsigned long	trans_tcp_count;
	unsigned long	trans_udp_count;
} MIB;

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

int SNMPrequest(char*);

int main(int argc, char* argv[])
{
    char addr1[100];
    char addr2[100];
    strcpy(addr1,"127.0.0.1");
    strcpy(addr2,"127.0.0.1");
	while(1){
        SNMPrequest(addr1);
		Sleep(100);
        SNMPrequest(addr2);
		Sleep(100);
    }
	return 0;
}

int SNMPrequest(char* address){
    int retval;
	SOCKET sock;
	SOCKADDR_IN serveraddr;
	char buf[BUFSIZE+1];
	int len;

	MIB *response = (MIB*)malloc(sizeof(MIB));

	// 윈속 초기화
	WSADATA wsa;
	if(WSAStartup(MAKEWORD(2,2), &wsa) != 0)
		return -1;

	// socket()
	sock = socket(AF_INET, SOCK_STREAM, 0);
	if(sock == INVALID_SOCKET) err_quit("socket()");	
	
	// server address
	ZeroMemory(&serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	serveraddr.sin_port = htons(9000);
	serveraddr.sin_addr.s_addr = inet_addr((const char*)address);

	// connect()
	retval = connect(sock, (SOCKADDR *)&serveraddr, sizeof(serveraddr));
	if(retval == SOCKET_ERROR) err_quit("connect()");
		
	// 서버와 데이터 통신
	ZeroMemory(buf, sizeof(buf));

	printf("\n severaddr: %s Request \n", address);
		
	strcpy(buf,"request");

	// '\n' 문자 제거
	len = strlen(buf);
	if(buf[len-1] == '\n')
		buf[len-1] = '\0';

	// request 보내기
	retval = send(sock, buf, strlen(buf), 0);
	if(retval == SOCKET_ERROR){
		err_display("send()");
		return 0;
	}

	// 데이터 받기
	retval = recv(sock, buf, BUFSIZE, 0);
	if(retval == SOCKET_ERROR){
		err_display("recv()");
		return 0;
	}
	else if(retval == 0)
		return 0;
		
	// 받은 데이터 출력
	buf[retval] = '\0';
	response = (MIB*)buf;

	printf("Total pkt:%d pktper:%d byteper:%d ip:%lu tcp:%lu udp:%lu \n"
	, response->tot_capured_pk_num, response->numpkt_per_sec, response->numbyte_per_sec, response->net_ip_count, response->trans_tcp_count, response->trans_udp_count);

	// closesocket()
	closesocket(sock);

	// 윈속 종료
	WSACleanup();
}