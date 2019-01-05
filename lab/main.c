#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include "menu.h"

#define FONTSIZE 10
int PrintMenuOS()
{
    int i, j;
    char data_M[FONTSIZE][FONTSIZE] =
    {
        "          ",
        "  *    *  ",
        " ***  *** ",
        " * *  * * ",
        " * *  * * ",
        " *  **  * ",
        " *      * ",
        " *      * ",
        " *      * ",
        "          "
    };
    char data_e[FONTSIZE][FONTSIZE] =
    {
        "          ",
        "          ",
        "    **    ",
        "   *  *   ",
        "  *    *  ",
        "  ******  ",
        "  *       ",
        "   *      ",
        "    ***   ",
        "          "
    };
    char data_n[FONTSIZE][FONTSIZE] =
    {
        "          ",
        "          ",
        "    **    ",
        "   *  *   ",
        "  *    *  ",
        "  *    *  ",
        "  *    *  ",
        "  *    *  ",
        "  *    *  ",
        "          "
    };
    char data_u[FONTSIZE][FONTSIZE] =
    {
        "          ",
        "          ",
        "  *    *  ",
        "  *    *  ",
        "  *    *  ",
        "  *    *  ",
        "  *    *  ",
        "   *  **  ",
        "    **  * ",
        "          "
    };
    char data_O[FONTSIZE][FONTSIZE] =
    {
        "          ",
        "   ****   ",
        "  *    *  ",
        " *      * ",
        " *      * ",
        " *      * ",
        " *      * ",
        "  *    *  ",
        "   ****   ",
        "          "
    };
    char data_S[FONTSIZE][FONTSIZE] =
    {
        "          ",
        "    ****  ",
        "   **     ",
        "  **      ",
        "   ***    ",
        "     **   ",
        "      **  ",
        "     **   ",
        "  ****    ",
        "          "
    };

    for(i=0; i<FONTSIZE; i++)
    {
        for(j=0; j<FONTSIZE; j++)
        {
            printf("%c", data_M[i][j]);
        }
        for(j=0; j<FONTSIZE; j++)
        {
            printf("%c", data_e[i][j]);
        }
        for(j=0; j<FONTSIZE; j++)
        {
            printf("%c", data_n[i][j]);
        }
        for(j=0; j<FONTSIZE; j++)
        {
            printf("%c", data_u[i][j]);
        }
        for(j=0; j<FONTSIZE; j++)
        {
            printf("%c", data_O[i][j]);
        }
        for(j=0; j<FONTSIZE; j++)
        {
            printf("%c", data_S[i][j]);
        }
        printf("\n");
    }
    return 0;
}

int Quit(int argc, char *argv[])
{
    /* add XXX clean ops */
}
/* TCP */
#include"syswrapper.h"
#define MAX_CONNECT_QUEUE   1024
int Replyhi()
{
	char szBuf[MAX_BUF_LEN] = "\0";
	char szReplyMsg[MAX_BUF_LEN] = "hi\0";
	InitializeService();
	while (1)
	{
		ServiceStart();
		RecvMsg(szBuf);
		SendMsg(szReplyMsg);
		ServiceStop();
	}
	ShutdownService();
	return 0;
}

int StartReplyhi(int argc, char *argv[])
{
	int pid;
	/* fork another process */
	pid = fork();
	if (pid < 0)
	{
		/* error occurred */
		fprintf(stderr, "Fork Failed!");
		exit(-1);
	}
	else if (pid == 0)
	{
		/*	 child process 	*/
		Replyhi();
		printf("Reply hi TCP Service Started!\n");
	}
	else
	{
		/* 	parent process	 */
		printf("Please input hello...\n");
	}
}

int Hello(int argc, char *argv[])
{
	char szBuf[MAX_BUF_LEN] = "\0";
	char szMsg[MAX_BUF_LEN] = "hello\0";
	OpenRemoteService();
	SendMsg(szMsg);
	RecvMsg(szBuf);
	CloseRemoteService();
	return 0;
}

/*UDP*/
#define SERVER_PORT 8888 
#define MAX_MSG_SIZE 1024  
#define BUFF_LEN 1024
/*

    UDP client:

            socket-->sendto-->revcfrom-->close

*/
void udp_msg_sender(int fd, struct sockaddr* dst)
{

    socklen_t len;
    struct sockaddr_in src;
    char buf[BUFF_LEN] = "TEST UDP MSG \n";
    len = sizeof(*dst);
    printf("client:%s\n",buf);  //打印自己发送的信息     
    sendto(fd, buf, BUFF_LEN, 0, dst, len);
    memset(buf, 0, BUFF_LEN);
    while(1)
    {
        recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&src, &len);  //接收来自server的信息         
        printf("get server msg:%s\n",buf);
        return 0;
    }
}
 
int udp_hello (){
    int client_fd;
    struct sockaddr_in ser_addr;

    client_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(client_fd < 0)
    {
        printf("create socket fail!\n");
        return -1;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    //注意这一行，填入实际的服务器端的IP就可以和实际的服务器通信了
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);    
    //这里使用NADDR_ANY是和本机通信 
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);  //注意网络序转换     
    ser_addr.sin_port = htons(SERVER_PORT);  //注意网络序转换 
    udp_msg_sender(client_fd, (struct sockaddr*)&ser_addr);

    close(client_fd);

    return 0;

}

/*

    UDP server:

            socket-->bind-->recvfrom-->sendto-->close

*/
void handle_udp_msg(int fd)
{
    char buf[BUFF_LEN];  //接收缓冲区，1024字节    
    socklen_t len;
    int count;
    struct sockaddr_in clent_addr;  //clent_addr用于记录发送方的地址信息     
    while(1)
    {
        memset(buf, 0, BUFF_LEN);
        len = sizeof(clent_addr);
        count = recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, &len);  //recvfrom是拥塞函数，没有数据就一直拥塞         
        if(count == -1)
        {
            printf("recieve data fail!\n");
            return;
        }
        printf("get_client_message:%s\n",buf);  //打印client发过来的信息         
        memset(buf, 0, BUFF_LEN);
        sprintf(buf, "I have recieved %d bytes data!\n", count);  //回复client         
        printf("server:%s\n",buf);  //打印自己发送的信息给         
        sendto(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, len);  //发送信息给client，注意使用了clent_addr结构体指针 
    }
}

int udp_reply(){
	int server_fd, ret;
    struct sockaddr_in ser_addr; 

    server_fd = socket(AF_INET, SOCK_DGRAM, 0); //AF_INET:IPV4;SOCK_DGRAM:UDP     
    if(server_fd < 0)
    {
        printf("create socket fail!\n");
        return -1;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY); //IP地址，需要进行网络序转换，INADDR_ANY：本地地址     
    ser_addr.sin_port = htons(SERVER_PORT);  //端口号，需要网络序转换 
    ret = bind(server_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret < 0)
    {
        printf("socket bind fail!\n");
        return -1;
    }

    handle_udp_msg(server_fd);   //处理接收到的数据 
    close(server_fd);
    return 0;
}

int udp_reply_start(int argc, char *argv[])
{
	int pid;
	/* fork another process */
	pid = fork();
	if (pid < 0)
	{
		/* error occurred */
		fprintf(stderr, "Fork Failed!");
		exit(-1);
	}
	else if (pid == 0)
	{
		/*	 child process 	*/
		udp_reply();
		printf("Reply  UDP Service Started!\n");
	}
	else
	{
		/* 	parent process	 */
		printf("Please input udpHello...\n");
	}
}

/*
*   HTTP Client
*/
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 

#define DEST_PORT 80
#define DEST_IP_ADDR "180.97.33.107/" //13.250.177.223 13.229.188.59 52.74.223.119nslookup 
//#define DEST_IP_BY_NAME "github.com"
#define DEST_IP_BY_NAME "www.baidu.com"
void HttpRequest(int sock_fd, char *filename,FILE *fp)
{
    
    int sendNum;
    char sendBuf[] = "goog luck";
    char rcvBuf[4096];
    char str1[4096];
    int recvNum = 0;
    printf("begin send request\n");
    memset(str1,0,4096);
    //https://13.250.177.223:80/index.html
    //strcat(str1,"GET https://13.250.177.223:80/index.html HTTP/1.1\r\n");
    strcat(str1,"GET http://www.baidu.com/index.html HTTP/1.1\r\n");
    strcat(str1,"Accept:html/text*/*\r\n");
    strcat(str1,"Accept-language:zh-ch\r\n");
    strcat(str1,"Accept-Encoding:gzip,deflate\r\n");
    //strcat(str1,"Host: 13.250.177.223:80\r\n");
    strcat(str1,"Host: 180.97.33.107:80\r\n");
    strcat(str1,"User-Agent:chzhyang's client<1.0>\r\n");
    strcat(str1,"Connection:Close\r\n");
    strcat(str1,"\r\n");
    printf("str1 = %s\n",str1);
    sendNum = send(sock_fd, str1,strlen(str1),0);
    if (sendNum < 0) 
    {
        perror("send error");
        exit(1);
    } 
    else 
    {
        printf("send success\n");
        printf("begin recv:\n");
        //fp = fopen(filename,"w+");
        do
        {
            //recvNum:size of recved msg
            recvNum = recv(sock_fd,rcvBuf,sizeof(rcvBuf),0);
            if(recvNum < 0) 
            {
                perror("recv error\n");
                exit(1);
            } 
            else 
            {
                //write date into file
                //fwrite(rcvBuf, 1, recvNum, fp);
                printf("recv success:\n%s\n",rcvBuf);

            }
            //only get header , if want all , delete break, and openfile+write
            break;
            sleep(5);
        }while(recvNum>0); 
        //fclose(fp);
    }   
}
int httpClient()
{
    FILE *fp = NULL;
    char filename[256] = "./index.html";
    //init sockt
    int sock_fd = -1;
    struct sockaddr_in addr_serv;
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("init sock error\n");
        exit(1);
    }
    else
    {
        printf("init sock successful\n");      
    }
    //url->ip
    struct hostent* hostInfo = gethostbyname(DEST_IP_BY_NAME);
    if(NULL == hostInfo)
    {
        printf("Gethostname error\n");
        return 0;
    }
    memset(&addr_serv, 0, sizeof(addr_serv));
    addr_serv.sin_family = AF_INET;
    addr_serv.sin_port = htons(DEST_PORT);
    //addr_serv.sin_addr.s_addr = inet_addr(DEST_IP_ADDR);
    printf("Ip address = %s \n",inet_ntoa(*((struct in_addr*)hostInfo->h_addr)));
    memcpy(&addr_serv.sin_addr, &(*hostInfo->h_addr_list[0]), hostInfo->h_length);

    //connect
    if (connect(sock_fd, (struct sockaddr*)(&addr_serv), sizeof(addr_serv)) < 0)
    {
        perror("connect error\n");
        exit(1);
    }
    else
    {
        printf("connect success\n");
    }

    //send http request, recv reflaction
    HttpRequest(sock_fd,filename,fp);
    //close
    close(sock_fd);
    return 0;
}

#include <sys/ioctl.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <net/if.h>
#include <arpa/inet.h>
 
#include <unistd.h>
#include <stdio.h>
#define MAX_IFS 64
 
int BringUpNetInterface()
{
    printf("Bring up interface:lo\n");
    struct sockaddr_in sa;
    struct ifreq ifreqlo;
    int fd;
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("127.0.0.1");
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(ifreqlo.ifr_name, "lo",sizeof("lo"));
    memcpy((char *) &ifreqlo.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
    ioctl(fd, SIOCSIFADDR, &ifreqlo);
    ioctl(fd, SIOCGIFFLAGS, &ifreqlo);
    ifreqlo.ifr_flags |= IFF_UP|IFF_LOOPBACK|IFF_RUNNING;
    ioctl(fd, SIOCSIFFLAGS, &ifreqlo);
    close(fd);
    
    printf("Bring up interface:eth0\n");
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr("192.168.40.254");
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strncpy(ifreqlo.ifr_name, "eth0",sizeof("eth0"));
    memcpy((char *) &ifreqlo.ifr_addr, (char *) &sa, sizeof(struct sockaddr));
    ioctl(fd, SIOCSIFADDR, &ifreqlo);
    ioctl(fd, SIOCGIFFLAGS, &ifreqlo);
    ifreqlo.ifr_flags |= IFF_UP|IFF_RUNNING;
    ioctl(fd, SIOCSIFFLAGS, &ifreqlo);
    close(fd);

    printf("List all interfaces:\n");
    struct ifreq *ifr, *ifend;
    struct ifreq ifreq;
    struct ifconf ifc;
    struct ifreq ifs[MAX_IFS];
    int SockFD;
 
 
    SockFD = socket(PF_INET, SOCK_DGRAM, 0);
 
 
    ifc.ifc_len = sizeof(ifs);
    ifc.ifc_req = ifs;
    if (ioctl(SockFD, SIOCGIFCONF, &ifc) < 0)
    {
        printf("ioctl(SIOCGIFCONF): %m\n");
        return 0;
    }
 
    ifend = ifs + (ifc.ifc_len / sizeof(struct ifreq));
    for (ifr = ifc.ifc_req; ifr < ifend; ifr++)
    {
        printf("interface:%s\n", ifr->ifr_name);
#if 0
        if (strcmp(ifr->ifr_name, "lo") == 0)
        {
            strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));
            ifreq.ifr_flags == IFF_UP;
            if (ioctl (SockFD, SIOCSIFFLAGS, &ifreq) < 0)
            {
              printf("SIOCSIFFLAGS(%s): IFF_UP %m\n", ifreq.ifr_name);
              return 0;
            }			
	    }
#endif
	    if (ifr->ifr_addr.sa_family == AF_INET)
        {
            strncpy(ifreq.ifr_name, ifr->ifr_name,sizeof(ifreq.ifr_name));
            if (ioctl (SockFD, SIOCGIFHWADDR, &ifreq) < 0)
            {
              printf("SIOCGIFHWADDR(%s): %m\n", ifreq.ifr_name);
              return 0;
            }
 
            printf("Ip Address %s\n", inet_ntoa( ( (struct sockaddr_in *)  &ifr->ifr_addr)->sin_addr)); 
            printf("Device %s -> Ethernet %02x:%02x:%02x:%02x:%02x:%02x\n", ifreq.ifr_name,
                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[0],
                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[1],
                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[2],
                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[3],
                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[4],
                (int) ((unsigned char *) &ifreq.ifr_hwaddr.sa_data)[5]);
        }
    }
 
    return 0;
}
int main()
{
    BringUpNetInterface();
    PrintMenuOS();
    SetPrompt("MenuOS>>");
    MenuConfig("version","MenuOS V1.0(Based on Linux 3.18.6)",NULL);
    MenuConfig("quit","Quit from MenuOS",Quit);
    MenuConfig("replyhi", "Reply hi TCP Service", StartReplyhi);
    MenuConfig("hello", "Hello TCP Client", Hello);
    MenuConfig("udpReply", "Reply hi UDP Service", udp_reply_start);
    MenuConfig("udpHello", "Hello UDP Client", udp_hello);
    MenuConfig("httpHello", "HTTP Client", httpClient);
    ExecuteMenu();
}

