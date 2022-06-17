# Mapping from bpftool prog types to BPF programs and types enums

If you have seen following statement in your eBPF C code

```C
__section("cgroup/connect4")
```

and wondering how they are internally mapped to the `BPF_PROG_TYPE_` and `BPF_(ATTACH TYPE)` enums do dig further in the kernel code, this doc might help you undangle this pointer.

As of kernel 5.17 version |  tool supports attaching bpf program to following networking related eBPF hooks.

```text
socket              xdp                 sockops                 sk_skb                  sk_msg
cgroup/skb          cgroup/sock         cgroup/bind4            cgroup/bind6            cgroup/post_bind4
cgroup/post_bind6   cgroup/connect4     cgroup/connect6         cgroup/getpeername4     cgroup/getpeername6
cgroup/getsockname4 cgroup/getsockname6 cgroup/sendmsg4         cgroup/sendmsg6         cgroup/recvmsg4
cgroup/recvmsg6     cgroup/getsockopt   cgroup/setsockopt       cgroup/sock_release     sk_lookup
```

Following table shows how these program types are internally mapped to kernel PROG and ATTACHMENT TYPE

| Bpftool Prog Types |  BPF Prog Types | BPF Attach Type |
|--- | --- | --- |
| socket | BPF_PROG_TYPE_SOCKET_FILTER | N/A |
| xdp | BPF_PROG_TYPE_XDP | BPF_XDP |
| xdp.frags/devmap | BPF_PROG_TYPE_XDP |BPF_XDP_DEVMAP |
| xdp/devmap | BPF_PROG_TYPE_XDP | BPF_XDP_DEVMAP |
| xdp_devmap/ | BPF_PROG_TYPE_XDP | BPF_XDP_DEVMAP |
| xdp.frags/cpumap | BPF_PROG_TYPE_XDP | BPF_XDP_CPUMAP |
| xdp/cpumap |  BPF_PROG_TYPE_XDP |  BPF_XDP_CPUMAP |
| xdp_cpumap/ |  BPF_PROG_TYPE_XDP |  BPF_XDP_CPUMAP |
| xdp.frags |  BPF_PROG_TYPE_XDP |  BPF_XDP |
| cgroup_skb/ingress | BPF_PROG_TYPE_CGROUP_SKB | BPF_CGROUP_INET_INGRESS |
| cgroup_skb/egress | BPF_PROG_TYPE_CGROUP_SKB | BPF_CGROUP_INET_EGRESS |
| cgroup/skb | BPF_PROG_TYPE_CGROUP_SKB | NA |
| cgroup/sock_create | BPF_PROG_TYPE_CGROUP_SOCK | BPF_CGROUP_INET_SOCK_CREATE |
| cgroup/sock_release | BPF_PROG_TYPE_CGROUP_SOCK | BPF_CGROUP_INET_SOCK_RELEASE |
| cgroup/sock | BPF_PROG_TYPE_CGROUP_SOCK | BPF_CGROUP_INET_SOCK_CREATE |
| cgroup/post_bind4 | BPF_PROG_TYPE_CGROUP_SOCK | BPF_CGROUP_INET4_POST_BIND |
| cgroup/post_bind6 | BPF_PROG_TYPE_CGROUP_SOCK | BPF_CGROUP_INET6_POST_BIND |
| cgroup/dev | BPF_PROG_TYPE_CGROUP_DEVICE | BPF_CGROUP_DEVICE |
| sockops | BPF_PROG_TYPE_SOCK_OPS | BPF_CGROUP_SOCK_OPS |
| sk_skb/stream_parser | BPF_PROG_TYPE_SK_SKB | BPF_SK_SKB_STREAM_PARSER |
| sk_skb/stream_verdict | BPF_PROG_TYPE_SK_SKB | BPF_SK_SKB_STREAM_VERDICT |
| sk_skb | BPF_PROG_TYPE_SK_SKB | NA |
| sk_msg | BPF_PROG_TYPE_SK_MSG | BPF_SK_MSG_VERDICT |
| cgroup/bind4 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET4_BIND |
| cgroup/bind6 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET6_BIND |
| cgroup/connect4 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET4_CONNECT |
| cgroup/connect6 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET6_CONNECT |
| cgroup/sendmsg4 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_UDP4_SENDMSG |
| cgroup/sendmsg6 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_UDP6_SENDMSG |
| cgroup/recvmsg4 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_UDP4_RECVMSG |
| cgroup/recvmsg6 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_UDP6_RECVMSG |
| cgroup/getpeername4 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET4_GETPEERNAME |
| cgroup/getpeername6 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET6_GETPEERNAME |
| cgroup/getsockname4 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET4_GETSOCKNAME |
| cgroup/getsockname6 | BPF_PROG_TYPE_CGROUP_SOCK_ADDR | BPF_CGROUP_INET6_GETSOCKNAME |
| cgroup/getsockopt | BPF_PROG_TYPE_CGROUP_SOCKOPT | BPF_CGROUP_GETSOCKOPT |
| cgroup/setsockopt | BPF_PROG_TYPE_CGROUP_SOCKOPT | BPF_CGROUP_SETSOCKOPT |
| sk_lookup | BPF_PROG_TYPE_SK_LOOKUP | BPF_SK_LOOKUP |
