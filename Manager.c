#include <winsock2.h>
#include <stdlib.h>
#include <stdio.h>

#define BUFSIZE 1500

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

int main(int argc, char* argv[])
{
    char addr1[100];
    char addr2[100];
    strcpy(addr1,"127.0.0.1");
    strcpy(addr2,"127.0.0.1");
	while(1){
        SNMPrequest(addr1);
        SNMPrequest(addr2);
    }
}

void SNMPrequest(char* address){
    int retval;
	SOCKET sock;
	SOCKADDR_IN serveraddr;
	char buf[BUFSIZE+1];
	int len;

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
	serveraddr.sin_addr.s_addr = inet_addr(address);

	// connect()
	retval = connect(sock, (SOCKADDR *)&serveraddr, sizeof(serveraddr));
	if(retval == SOCKET_ERROR) err_quit("connect()");
		
	// 서버와 데이터 통신
	while(1){
		// 데이터 입력
		ZeroMemory(buf, sizeof(buf));
		

	}

	// closesocket()
	closesocket(sock);

	// 윈속 종료
	WSACleanup();
}