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

## 2. start-init

start-kernel(main.c)---->do_basic_setup(main.c)---->sock_init(/net/socket.c)---->do_initcalls(main.c)

## 3.creart connect

sys_socketcall #2492

call = 0，sys_socket， #1377 ，调用sock_creat() #1365 它会创建一个socket struct, 参数为family,type,protocol。

sock_creat()会根据协议不同(family)调用不同create函数。TCP为family=AF_INET,则调用inet_create（），net/ipv4/af_inet.c#249。

inet_create（），sock->state = SS_UNCONNECTED;

call = 3，sys_connect #1688 调用inet_stream_connect(), 该函数会得到一个sk struct，它描述了socket的状态，如ss_connected、ss_connecting、ss_unconnected等，如为后者，则根据协议调用先关函数，sk->sk_prot->connect(sk, uaddr, addr_len)，如tcp，则调用inet_stream_connect，pos:linux-3.18.6/net/ipv4/af_inet.c#647。
然后调用tcp_v4_connect，pos：linux-3.18.6/net/ipv4/tcp_ipv4.c#141，它会调用函数寻找合适的路由。
（sk 为struct sock的指针，sk_prot: protocol handlers inside a network family）

## 4.send data

send()-->sys_send()-->sys_sendto()-->sock_sendmsg()-->inet_sendmsg()-->tcp_sendmsg()

reference:
https://blog.csdn.net/ztguang/article/details/52678848
https://blog.csdn.net/Shreck66/article/details/47428533
