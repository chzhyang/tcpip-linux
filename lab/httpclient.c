#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h> 

#define DEST_PORT 80
#define DEST_IP_ADDR "192.30.255.113" 
#define DEST_IP_BY_NAME "github.com"

void HttpRequest(int sock_fd)
{
    int sendNum;
    char sendBuf[] = "goog luck";
    char rcvBuf[4096];
    char str1[4096];
    while (1) 
    {
        printf("begin send request\n");
        memset(str1,0,4096);
        strcat(str1,"GET github.com:80/index.html HTTP/1.1\r\n");
        strcat(str1,"Accept:html/text*/*\r\n");
        strcat(str1,"Accept-language:zh-ch\r\n");
        strcat(str1,"Accept-Encoding:gzip,deflate\r\n");
        strcat(str1,"Host: 192.30.255.113:80\r\n");
        strcat(str1,"User-Agent:chzhyang's client<1.0>\r\n");
        strcat(str1,"Connection:Close\r\n");
        strcat(str1,"\r\n");
        printf("str1 = %s\n",str1);
        sendNum = send(sock_fd, str1,strlen(str1),0);
        if (sendNum < 0) 
        {
            perror("send error");
            return;
        } 
        else 
        {
            printf("send success\n");
            printf("begin recv:\n");
            int recv_num = recv(sock_fd,rcvBuf,sizeof(rcvBuf),0);
            if(recv_num < 0) 
            {
                perror("recv error\n");
                return;
            } 
            else 
            {
                printf("recv success:\n%s\n",rcvBuf);
            }
        }
        break;
    }
    
}
int main(int argc, char const *argv[])
{
    
    //init sockt
    int sock_fd = -1;
    struct sockaddr_in addr_serv;
    sock_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (sock_fd < 0)
    {
        perror("init sock error\n");
        return;
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
    printf("begin connect\n");
    if (connect(sock_fd, (struct sockaddr*)(&addr_serv), sizeof(addr_serv)) < 0)
    {
        perror("connect error\n");
        return;
    }
    else
    {
        printf("connect success\n");
    }

    //send http request, recv reflaction
    HttpRequest(sock_fd);
    //close
    close(sock_fd);
    return 0;
}
// https://blog.csdn.net/dreamstone_xiaoqw/article/details/78864787
// https://blog.csdn.net/mianhuantang848989/article/details/53745523
// https://blog.csdn.net/lovecodeless/article/details/25490643
// https://blog.csdn.net/fuziwang/article/details/83825573