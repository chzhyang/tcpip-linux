# UDP

## 编写udp通信函数
### 工作流程
server: socket()->bind()->recvfrom()->sendto()->close()  
client: socket()->sendto()->recvfrom()->close()
### 主要函数
- int socket(int domain,int type,int protocol)   
domain=AF_INET type=SOCK_DGRAM    protocol=0    
- sendto(intsockfd,constvoid*buf, size_t len,int flags,conststructsockaddr  
   \*dest_addr, socklen_t addrlen)   
sockfd:正在监听端口的套接口文件描述符   buf：发送缓冲区  
len:发送缓冲区的大小，单位是字节   flags:0   dest_addr:z指向接收数据的主机地址  
addrlen:地址长度  
- recvfrom(int sockfd,void* buf, size_t len,int flags,struct sockaddr \*src_addr,   
  socklen_t \*addrlen)  
- bind (int sockfd,const structsock addr* my_addr, socklen_t addrlen)  
  my_addr:要绑定的IP和端口  

### 主要程序
```C
/* Server */
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
    /*IP地址，需要进行网络序转换，INADDR_ANY：本地地址 */
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);     
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
        /*recvfrom是拥塞函数，没有数据就一直拥塞*/
        count = recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, &len);  
        if(count == -1)
        {
            printf("recieve data fail!\n");
            return;
        }
        printf("get_client_message:%s\n",buf);  //打印client发过来的信息         
        memset(buf, 0, BUFF_LEN);
        sprintf(buf, "I have recieved %d bytes data!\n", count);  //回复client         
        printf("server:%s\n",buf);  //打印自己发送的信息给
        /*发送信息给client，注意使用了clent_addr结构体指针*/        
        sendto(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, len);  
    }
}

/*Client*/
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
        //接收来自server的信息
        recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&src, &len);           
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
    //注意网络序转换  
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);     
    ser_addr.sin_port = htons(SERVER_PORT);  
    udp_msg_sender(client_fd, (struct sockaddr*)&ser_addr);

    close(client_fd);

    return 0;

}
```

## 跟踪函数调用
断点 inet_sendto udp_sendmsg udp_rsvfrom

### 数据发送
```
int inet_sendmsg(struct kiocb *iocb, struct socket *sock, struct msghdr *msg,
		 size_t size)
{
	struct sock *sk = sock->sk;

	sock_rps_record_flow(sk);

	// We may need to bind the socket.
	if (!inet_sk(sk)->inet_num && !sk->sk_prot->no_autobind &&
	    inet_autobind(sk))
		return -EAGAIN;

	return sk->sk_prot->sendmsg(iocb, sk, msg, size);
}

```

udp_sendmsg()  
ip_make_skb()  数据入队，加入头文件，出队   
\_ip_append_data() 将你需要传输的数据写入到缓冲队列中，并且添加所需的各种头文件    
\_ip_make_skb() 从缓冲队列中取出缓冲数据   

udp_send_skb() 加入udp报头  

### 数据接收
udp_rcv()  
udp_recvmsg()  
\__skb_recv_datagram()     
\__skb_pull() 去除ip头  
skb->data+sizeof(struct udphdr)  

### 释放udp socket
socket_file_ops  
release  
sock_close  
sock_release  
sock->ops->release   inet_release()
