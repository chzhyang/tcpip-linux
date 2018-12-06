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
https://blog.csdn.net/qy532846454/article/details/7882819

典型的客户端流程：  connect() -> send() -> recv()  
典型的服务器流程：  bind() -> listen() -> accept() -> recv() -> send()

客户端 <br>
(1)发送SYN报文，向服务器发起tcp连接  
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


tcp_v4_connect() -> tcp_connect(sk) 发送SYN报文
tcp_connect() [tcp_output.c]  
几步重要的代码如下，tcp_connect_init()中设置了tp->rcv_nxt=0，tcp_transmit_skb()负责  
发送报文，其中seq=tcb->seq=tp->write_seq，ack_seq=tp->rcv_nxt。
```c
tcp_connect_init(sk);
......
/* Send off SYN; include data in Fast Open. */
err = tp->fastopen_req ? tcp_send_syn_data(sk, buff) :
      tcp_transmit_skb(sk, buff, 1, sk->sk_allocation);
......
/* We change tp->snd_nxt after the tcp_transmit_skb() call
* in order to make this packet get counted in tcpOutSegs.
*/
tp->snd_nxt = tp->write_seq;

```

(2)收到服务端的SYN+ACK，发送ACK <br>

tcp_v4_rcv()
```c
sk = __inet_lookup_skb(&tcp_hashinfo, skb, th->source, th->dest); //在ehash中找到  
TCP_SYN_SENT状态的sk
//connect()即使阻塞也不占有锁
	if (!sock_owned_by_user(sk)) {
		 //对于synack，不会排入prepare队列
		if (!tcp_prequeue(sk, skb))
			ret = tcp_v4_do_rcv(sk, skb);
```

tcp_v4_do_rcv()
```c
//进入TCP_SYN_SENT状态处理逻辑
if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {
	rsk = sk;
	goto reset;
}
```
tcp_rcv_synsent_state_process()  此时已接收到对方的ACK，状态变迁到TCP_ESTABLISHED。  
最后发送对方SYN的ACK报文。<br>

```c
tcp_set_state(sk, TCP_ESTABLISHED);
tcp_send_ack(sk);
```

服务器端
(1)被动建立连接
bind() -> inet_bind()  bind操作的主要作用是将创建的socket与给定的地址相绑定。socket  
状态为TCP_ClOSE。
```c
snum = ntohs(addr->sin_port);
……
inet->inet_rcv_saddr = inet->inet_saddr = addr->sin_addr.s_addr;
if (sk->sk_prot->get_port(sk, snum)) {
 inet->inet_saddr = inet->inet_rcv_saddr = 0;
 err = -EADDRINUSE;
 goto out_release_sock;
}
……
inet->inet_sport = htons(inet->inet_num);
inet->inet_daddr = 0;
inet->inet_dport = 0;
```
listen() -> inet_listen()

开始服务器的监听，监听前检查状态是否正确。
```c
if (sock->state != SS_UNCONNECTED || sock->type != SOCK_STREAM)
 goto out;
old_state = sk->sk_state;
if (!((1 << old_state) & (TCPF_CLOSE | TCPF_LISTEN)))
 goto out;

//如果还没有执行listen，则还要调用inet_csk_listen_start()开始监听。
if (old_state != TCP_LISTEN) {
err = inet_csk_listen_start(sk, backlog);
if (err)
 goto out;
}
```

accept() -> sys_accept4() -> inet_accept() -> inet_csk_accept()

accept用于返回一个已经建立连接的socket(即经过了三次握手)。它监听icsk_accept_queue队列，  
当有socket经过了三次握手，它就会被加到icsk_accept_queue中，accept一旦发现队列中插入socket，  
就被唤醒并返回这个socket。
```C
if (reqsk_queue_empty(&icsk->icsk_accept_queue)) {
 long timeo = sock_rcvtimeo(sk, flags & O_NONBLOCK);
 ……
 error = inet_csk_wait_for_connect(sk, timeo);
 ……
}
```

协议栈向队列中加入socket的过程就是完成三次握手的过程，客户端通过向已知的listen fd发起连接请  
求，对于到来的每个连接，都会创建一个新的sock，当它经历了TCP_SYN_RCV -> TCP_ESTABLISHED后，  
就会被添加到icsk_accept_queue中，而监听的socket状态始终为TCP_LISTEN，保证连接的建立不会影  
响socket的接收。

(2)接收客户端发来的SYN，发送SYN+ACK

tcp_v4_do_rcv()  

tcp_v4_do_rcv()是TCP模块接收的入口函数，客户端发起请求的对象是listen fd，所以  
sk->sk_state == TCP_LISTEN，调用tcp_v4_hnd_req()来检查是否处于半连接，只要三次握手  
没有完成，这样的连接就称为半连接，具体而言就是收到了SYN，但还没有收到ACK的连接，所以对  
于这个查找函数，如果是SYN报文，则会返回listen的socket(连接尚未创建)；如果是ACK报文，  
则会返回SYN报文处理中插入的半连接socket。

存储这些半连接的数据结构是syn_table，它在listen()调用时被创建。

此时是收到SYN报文，tcp_v4_hnd_req()返回的仍是sk，调用tcp_rcv_state_process()来接收  
SYN报文，并发送SYN+ACK报文，同时向syn_table中插入一项表明此次连接的sk。

```c
if (sk->sk_state == TCP_LISTEN) {
 struct sock *nsk = tcp_v4_hnd_req(sk, skb);
 if (!nsk)
  goto discard;
 if (nsk != sk) {
  if (tcp_child_process(sk, nsk, skb)) {
   rsk = nsk;
   goto reset;
  }
  return 0;
 }
}
TCP_CHECK_TIMER(sk);
if (tcp_rcv_state_process(sk, skb, tcp_hdr(skb), skb->len)) {
 rsk = sk;
 goto reset;
}

```
 tcp_rcv_state_process() [tcp_input.c]

 处理各个状态上socket的情况。处于TCP_LISTEN的socket不会再向其它状态变迁，它负责监听，  
 并在连接建立时创建新的socket。

 ```c
case TCP_LISTEN:
……
 if (th->syn) {
  if (icsk->icsk_af_ops->conn_request(sk, skb) < 0)
   return 1;
  kfree_skb(skb);
  return 0;
 }
 ```
p_v4_conn_request()

tcp_v4_send_synack()向客户端发送了SYN+ACK报文，inet_csk_reqsk_queue_hash_add()将  
sk添加到了syn_table中。
```c
if (tcp_v4_send_synack(sk, dst, req, (struct request_values *)&tmp_ext) || want_cookie)
 goto drop_and_free;
inet_csk_reqsk_queue_hash_add(sk, req, TCP_TIMEOUT_INIT);
```
(3)接收客户端发来的ACK

tcp_v4_do_rcv()

过程与收到SYN报文相同，不同点在于syn_table中已经插入了有关该连接的条目，tcp_v4_hnd_req()  
会返回一个新的sock: nsk，然后会调用tcp_child_process()来进行处理。
```c
if (sk->sk_state == TCP_LISTEN) {
 struct sock *nsk = tcp_v4_hnd_req(sk, skb);
 if (!nsk)
  goto discard;
 if (nsk != sk) {
  if (tcp_child_process(sk, nsk, skb)) {
   rsk = nsk;
   goto reset;
  }
  return 0;
 }
}
```
tcp_v4_hnd_req()

inet_csk_search_req()会在syn_table中找到req，此时进入tcp_check_req()
```c
struct request_sock *req = inet_csk_search_req(sk, &prev, th->source, iph->saddr, iph->daddr);
if (req)
  return tcp_check_req(sk, skb, req, prev);
```
tcp_check_req()

syn_recv_sock() -> tcp_v4_syn_recv_sock()会创建一个新的sock并返回，创建的sock状态被  
直接设置为TCP_SYN_RECV，然后因为此时socket已经建立，将它添加到icsk_accept_queue中。

tcp_child_process()

如果此时sock: child被用户进程锁住了，那么就先添加到backlog中__sk_add_backlog()，待解锁时  
再处理backlog上的sock；否则先调用tcp_rcv_state_process()进行处理，处理完后，如果child状  
态到达TCP_ESTABLISHED，则表明其已就绪，调用sk_data_ready()唤醒等待在isck_accept_queue上  
的函数accept()。

```c
if (!sock_owned_by_user(child)) {
 ret = tcp_rcv_state_process(child, skb, tcp_hdr(skb), skb->len);
 if (state == TCP_SYN_RECV && child->sk_state != state)
  parent->sk_data_ready(parent, 0);
} else {
 __sk_add_backlog(child, skb);
}
```
tcp_rcv_state_process()处理各个状态上socket的情况

处于TCP_SYN_RECV状态时，传入的sk是新创建的sock(tcp_v4_hnd_req())，状态是TCP_SYN_RECV，  
而不是listen socket。在收到ACK后，sk状态变迁为TCP_ESTABLISHED，而在tcp_v4_hnd_req()中  
也已将sk插入到了icsk_accept_queue上，此时它就已经完全就绪了，回到tcp_child_process()  
便可执行sk_data_ready()。

```c
case TCP_SYN_RECV:
 if (acceptable) {
  ……
  tcp_set_state(sk, TCP_ESTABLISHED);
  sk->sk_state_change(sk);
  ……
  tp->snd_una = TCP_SKB_CB(skb)->ack_seq;
  tp->snd_wnd = ntohs(th->window) << tp->rx_opt.snd_wscale;
  tcp_init_wl(tp, TCP_SKB_CB(skb)->seq);
  ……
}
```

## 4. send data

send()-->sys_send()-->sys_sendto()-->sock_sendmsg()-->inet_sendmsg()-->tcp_sendmsg()

reference:
