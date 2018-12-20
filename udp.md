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
/*
* 创建一个子进程执行udp_reply()，从而保证client的udp_hello()可以被调用
*/
int udp_reply_start()
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

    server_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if(server_fd < 0)
    {
        printf("create socket fail!\n");
        return -1;
    }

    memset(&ser_addr, 0, sizeof(ser_addr));
    ser_addr.sin_family = AF_INET;
    //网络序转换，INADDR_ANY：本地地址
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);     
    ser_addr.sin_port = htons(SERVER_PORT);
    ret = bind(server_fd, (struct sockaddr*)&ser_addr, sizeof(ser_addr));
    if(ret < 0)
    {
        printf("socket bind fail!\n");
        return -1;
    }
    //处理收到的数据
    handle_udp_msg(server_fd);   
    close(server_fd);
    return 0;
}

void handle_udp_msg(int fd)
{
    char buf[BUFF_LEN];  //接收缓冲区   
    socklen_t len;
    int count;
    struct sockaddr_in clent_addr;  //发送方地址    
    while(1)
    {
        memset(buf, 0, BUFF_LEN);
        len = sizeof(clent_addr);
        //阻塞函数，等待接收数据
        count = recvfrom(fd, buf, BUFF_LEN, 0, (struct sockaddr*)&clent_addr, &len);  
        if(count == -1)
        {
            printf("recieve data fail!\n");
            return;
        }
        printf("get_client_message:%s\n",buf);          
        memset(buf, 0, BUFF_LEN);
        sprintf(buf, "I have recieved %d bytes data!\n", count);          
        printf("server:%s\n",buf);        
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
    printf("client:%s\n",buf);  
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
    //填入实际的服务器端IP即可通信
    //ser_addr.sin_addr.s_addr = inet_addr(SERVER_IP);    
    //NADDR_ANY是和本机通信
    ser_addr.sin_addr.s_addr = htonl(INADDR_ANY);     
    ser_addr.sin_port = htons(SERVER_PORT);  
    udp_msg_sender(client_fd, (struct sockaddr*)&ser_addr);

    close(client_fd);

    return 0;

}
```

## 跟踪函数调用
gdb中设置的断点  
inet_sendmsg   
udp_sendmsg    
udp_rcv   
udp_rsvfrom    
\__skb_recv_datagram  
sock_release  
inet_release  

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
调用树：  
inet_sendmsg()  
udp_sendmsg()   
ip_make_skb()  数据入队，加入头文件，出队   
\_ip_append_data() 将要发送的数据写入缓冲队列，添加各种头文件    
\_ip_make_skb() 从缓冲队列中取出数据   
udp_send_skb() 加入udp报头   

### 数据接收  
调用树：  
udp_rcv()   
udp_recvmsg()   
\__skb_recv_datagram()   接收数据的主体
\__skb_pull() 去除ip头   
skb->data+sizeof(struct udphdr)   

### 释放udp socket
调用树：  
socket_file_ops  
release  
sock_close  
sock_release   
sock->ops->release   inet_release()  
注意，1. release是从底层往上层释放   2. server不需要释放socket
