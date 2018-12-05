# TCP

## 1. preparation

BSD socket层：适用于各种协议，主要结构struct socket
/net/socket.c  
/net/protocols.c

INET socker层：tcp/ip专属(AF_INET)，数据结构struct sock  
/net/core/sock.c  
/net/ipv4/af_inet.c  
/net/ipv4/protocol.c

tcp/udp层：数据结构struct inet_protocol、struct proto  
/net/ipv4/udp.c  
/net/ipv4/datagram.c  
/net/ipv4/tcp.c  
/net/ipv4/tcp_input.c  
/net/ipv4//tcp_output.c  
/net/ipv4/tcp_minisocks.c  
/net/ipv4/tcp_timer.c

ip层：数据结构struct packet_type  
/net/ipv4/ip_forward.c  
ip_fragment.c  
ip_input.c  
ip_output.c

数据链路层、驱动：struct device  
dev.c  
/driver/net

## 2. 启动

### 2.1 初始化进程

start-kernel(main.c)-->do_basic_setup(main.c)-->sock_init(/net/socket.c)-->do_initcalls(main.c)

## 3. 网络连接的初始化和建立

### 3.1 初始化

创建socket：socket(AF_INET, SOCK_DGRAM, IPPROTO_TCP) 调用接口[net/socket.c]
通过sys_socketcall即SYSCALL_DEFINE2(socketcall)调用sys_socket即SYSCALL_DEFINE3(socket) 。  

其中调用sock_creat() 用于创建socket结构, 参数为family,type,protocol。  
调用sock_map_fd()将之映射到文件描述符，使socket能通过fd进行访问。  
 ```c
 retval = sock_create(family, type, protocol, &sock);
 if (retval < 0)
   goto out;

 retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
 if (retval < 0)
   goto out_release;
 ```
 retval = sock_create(family, type, protocol, &sock);
if (retval < 0)
 goto out;
retval = sock_map_fd(sock, flags & (O_CLOEXEC | O_NONBLOCK));
if (retval < 0)
 goto out_release;

 '''
sock_create(), /socket.c, 根据协议不同(family)调用不同create函数。TCP为family=AF_INET, 调用inet_create（），net/ipv4/af_inet.c#249。

inet_create(), /af_inet.c , sock->state = SS_UNCONNECTED;    
创建sock结构，socket->ops初始化为inet_stream_ops, sock->prot初始化为tcp_prot；  
然后调用sock_init_data(), 将该socket结构的变量sock和sock类型的变量关联起来。  
socket{}结构表示INET中的实体，而sock{ }结构就是网络层实体，sock用来保存打开的连接的状态信息。它一般定义的变量叫sk。

### 3.2 建立连接

http://www.cnhalo.net/2016/06/13/linux-tcp-synack-rcv/  
典型的客户端流程：  connect() -> send() -> recv()  
典型的服务器流程：  bind() -> listen() -> accept() -> recv() -> send()

(1)第一次握手 客户端 <br>
发送SYN报文，向服务器发起tcp连接  
connect(fd, servaddr, addrlen);
系统调用call =3, sys_connect(), SYSCALL＿DEFINE3()   
sock->ops->connect() == inet_stream_connect (sock->ops即inet_stream_ops)  
tcp_v4_connect()

connect() 将一个和socket结构关联的文件描述符和一个sockaddr{}结构的服务器地址关联，并且调用协议对应的connect连接函数。  
这里是tcp类型，sock->ops->connect为inet_stream_connect()。

inet_stream_connect(), /af_inet.c  
会得到一个sk = sock->sk,锁定sk，把sk的端口号存放在sk->num中，并且用htons()函数转换存放在sk->sport中。  
然后调用sk->prot->connect()函数指针，对tcp协议来说就是tcp_v4_connect()函数。  
然后将sock->state状态字设置为SS_CONNECTING,等待后面一系列的处理完成之后，就将状态改成SS_CONNECTTED。  
然后调用tcp_v4_connect，/net/ipv4/tcp_ipv4.c,它会调用函数寻找合适的路由。 <br>

sock从CLOSING转到TCP_SYN_SENT(TCP的状态转移图),并插入到bind链表中，如果是阻塞socket则connect()等待握手完成。
```c
tcp_set_state(sk, TCP_SYN_SENT);  //将sock状态设置为TCP_SYN_SENT

err = inet_hash_connect(&tcp_death_row, sk); 	//将sock插入到bhash中-> __inet_hash_connect()
```

接下来是端口设置，connect()通过__inet_hash_connect()分配端口号。[net/ipv4/inet_hashtables.c]，核心的代码是：
port = low + (i + offset) % remaining;其中 offset 是随机数。
```c
if (!snum) {
 inet_get_local_port_range(&low, &high);
 remaining = (high - low) + 1;
 ……
 for (i = 1; i <= remaining; i++) {
   ……// choose a valid port
}
}
```
tcp的内核表组成：  
udp的表内核表udptable只是一张hash表，tcp的表则稍复杂，它的名字是tcp_hashinfo，在tcp_init()中被初始化，这个数据结构定义如下:
```c
struct inet_hashinfo {
 struct inet_ehash_bucket *ehash;
 ……
 struct inet_bind_hashbucket *bhash;
 ……
 struct inet_listen_hashbucket  listening_hash[INET_LHTABLE_SIZE]
     ___cacheline_aligned_in_smp;
};
```
tcp表又分成了三张表ehash, bhash, listening_hash，其中ehash, listening_hash对应于socket处在TCP的ESTABLISHED, LISTEN状态，bhash对应于socket已绑定了本地地址。  
现在是建立socket连接阶段，使用的就应该是tcp表中的bhash。首先取得内核tcp表的bind表 – bhash，查看是否已有socket占用：  
如果没有，则调用inet_bind_bucket_create()创建一个bind表项tb，并插入到bind表中，跳转至goto ok代码段；
如果有，则跳转至goto ok代码段。

(2)第一次握手 服务器端 <br>

(2)第二次握手 客户端 <br>

tcp_v4_rcv()<br>
inet_lookup_skb() //在ehash中找到TCP_SYN_SENT状态的sk <br>
!sock_owned_by_user() //connect()即使阻塞也不占有锁 <br>
!tcp_prepare() //对于synack，不会排入prepare队列 <br>
tcp_v4_do_rcv() <br>
tcp_rcv_state_process() //进入TCP_SYN_SENT状态处理逻辑 <br>
tcp_rcv_synsent_state_process()<br>

## 4. send data

send()-->sys_send()-->sys_sendto()-->sock_sendmsg()-->inet_sendmsg()-->tcp_sendmsg()

reference:
