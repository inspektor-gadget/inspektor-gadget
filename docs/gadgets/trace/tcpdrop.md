---
title: 'Using trace tcpdrop'
weight: 20
description: >
    Trace TCP kernel-dropped packets/segments.
---

The trace tcpdrop gadget traces TCP packets dropped by the kernel.

### On Kubernetes

In terminal 1, start the trace tcpdrop gadget:

```bash
$ kubectl gadget trace tcpdrop
K8S.NODE         K8S.NAMESPACE  K8S.POD K8s.CONTAINER  PID     COMM  IP SRC                    DST                        STATE        TCPFLAGS  REASON
```

In terminal 2, start a pod and configure the network emulator to drop 25% of the packets:

```bash
$ kubectl create service nodeport nginx --tcp=80:80
$ kubectl create deployment nginx --image=nginx
$ kubectl run --rm -ti --privileged --image ubuntu shell -- bash
root@shell:/# apt-get update
root@shell:/# apt install -y iproute2 curl
root@shell:/# tc qdisc add dev eth0 root netem drop 25%
root@shell:/# curl nginx
```

The results in terminal 1 will show that some packets are dropped by the network emulator qdisc:

```
K8S.NODE         K8S.NAMESPACE  K8S.POD K8s.CONTAINER  PID     COMM  IP SRC                    DST                        STATE        TCPFLAGS  REASON
minikube-docker  default        shell   shell          0             4  p/default/shell:45979  s/kube-system/kube-dns:53  ESTABLISHED  FIN       QDISC_DROP
minikube-docker  default        shell   shell          406293  curl  4  p/default/shell:34482  s/default/nginx:80         ESTABLISHED  ACK       QDISC_DROP
```

The network emulator uses a random generator to drop 25% of the packets.
The results may vary.

The gadget tries its best to link the dropped packets to the process which generated it.
In some cases, this information might be missing.

The source and destination addresses are written in condensed form.
It is possible to see more detailed information by reading specific columns or using the json or yaml ouput:

```
$ kubectl gadget trace tcpdrop \
    -o columns=k8s.node,k8s.namespace,k8s.pod,k8s.container,pid,comm,ip,src.addr,src.port,src.kind,src.ns,src.name,dst.addr,dst.port,dst.kind,dst.ns,dst.name,state,tcpflags,reason
```

```
$ kubectl gadget trace tcpdrop -o yaml
---
comm: curl
container: shell
dst:
  addr: 10.101.116.61
  kind: svc
  namespace: default
  podlabels:
    app: nginx
  podname: nginx
  port: 80
gid: 0
ipversion: 4
mountnsid: 4026533845
namespace: default
netnsid: 4026533672
node: minikube-docker
pid: 412491
pod: shell
reason: QDISC_DROP
src:
  addr: 10.244.0.91
  kind: pod
  namespace: default
  podlabels:
    run: shell
  podname: shell
  port: 35802
state: ESTABLISHED
tcpflags: ACK
timestamp: 1681911565379499967
type: normal
uid: 0
```

### With `ig`

In terminal 1, start the trace tcpdrop gadget:

```bash
$ sudo ig trace tcpdrop -r docker
CONTAINER  PID     COMM  IP SRC               DST          STATE        TCPFLAGS  REASON
```

In terminal 2, start a container, configure the network emulator to drop 25% of the packets, and download a web page:

```bash
$ docker run -ti --rm --cap-add NET_ADMIN --name=netem wbitt/network-multitool -- /bin/bash
# tc qdisc add dev eth0 root netem drop 25%
# wget 1.1.1.1
```

The container needs NET_ADMIN capability to manage network interfaces

The results in terminal 1 will show that some packets are dropped by the network emulator qdisc:

```
CONTAINER  PID     COMM  IP SRC               DST          STATE        TCPFLAGS  REASON
netem      456426  wget  4  172.17.0.2:35790  1.1.1.1:443  ESTABLISHED  ACK       QDISC_DROP
```

The following section tells us that QDISC_DROP means the packet was "dropped by qdisc when packet outputting (failed to enqueue to current qdisc)".

### List of drop reasons

The drop reason enum is not stable and may change between kernel versions.
The tcpdrop gadget needs BTF information to decode the drop reason.
The following table shows the list of drop reasons for Linux 6.2.

<!-- markdown-link-check-disable -->

| Name    | Documentation |
|---------|---------------|
| [SKB_NOT_DROPPED_YET](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_NOT_DROPPED_YET&type=code) | skb is not dropped yet (used for no-drop case) |
| [SKB_CONSUMED](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_CONSUMED&type=code) | packet has been consumed |
| [SKB_DROP_REASON_NOT_SPECIFIED](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NOT_SPECIFIED&type=code) | drop reason is not specified |
| [SKB_DROP_REASON_NO_SOCKET](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NO_SOCKET&type=code) | socket not found |
| [SKB_DROP_REASON_PKT_TOO_SMALL](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_PKT_TOO_SMALL&type=code) | packet size is too small |
| [SKB_DROP_REASON_TCP_CSUM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_CSUM&type=code) | TCP checksum error |
| [SKB_DROP_REASON_SOCKET_FILTER](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_SOCKET_FILTER&type=code) | dropped by socket filter |
| [SKB_DROP_REASON_UDP_CSUM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_UDP_CSUM&type=code) | UDP checksum error |
| [SKB_DROP_REASON_NETFILTER_DROP](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NETFILTER_DROP&type=code) | dropped by netfilter |
| [SKB_DROP_REASON_OTHERHOST](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_OTHERHOST&type=code) | packet don't belong to current host (interface is in promisc mode) |
| [SKB_DROP_REASON_IP_CSUM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_CSUM&type=code) | IP checksum error |
| [SKB_DROP_REASON_IP_INHDR](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_INHDR&type=code) | there is something wrong with IP header (see IPSTATS_MIB_INHDRERRORS) |
| [SKB_DROP_REASON_IP_RPFILTER](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_RPFILTER&type=code) | IP rpfilter validate failed. see the document for rp_filter in ip-sysctl.rst for more information |
| [SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST&type=code) | destination address of L2 is multicast, but L3 is unicast. |
| [SKB_DROP_REASON_XFRM_POLICY](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_XFRM_POLICY&type=code) | xfrm policy check failed |
| [SKB_DROP_REASON_IP_NOPROTO](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_NOPROTO&type=code) | no support for IP protocol |
| [SKB_DROP_REASON_SOCKET_RCVBUFF](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_SOCKET_RCVBUFF&type=code) | socket receive buff is full |
| [SKB_DROP_REASON_PROTO_MEM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_PROTO_MEM&type=code) | proto memory limition, such as udp packet drop out of udp_memory_allocated. |
| [SKB_DROP_REASON_TCP_MD5NOTFOUND](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_MD5NOTFOUND&type=code) | no MD5 hash and one expected, corresponding to LINUX_MIB_TCPMD5NOTFOUND |
| [SKB_DROP_REASON_TCP_MD5UNEXPECTED](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_MD5UNEXPECTED&type=code) | MD5 hash and we're not expecting one, corresponding to LINUX_MIB_TCPMD5UNEXPECTED |
| [SKB_DROP_REASON_TCP_MD5FAILURE](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_MD5FAILURE&type=code) | MD5 hash and its wrong, corresponding to LINUX_MIB_TCPMD5FAILURE |
| [SKB_DROP_REASON_SOCKET_BACKLOG](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_SOCKET_BACKLOG&type=code) | failed to add skb to socket backlog ( see LINUX_MIB_TCPBACKLOGDROP) |
| [SKB_DROP_REASON_TCP_FLAGS](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_FLAGS&type=code) | TCP flags invalid |
| [SKB_DROP_REASON_TCP_ZEROWINDOW](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_ZEROWINDOW&type=code) | TCP receive window size is zero, see LINUX_MIB_TCPZEROWINDOWDROP |
| [SKB_DROP_REASON_TCP_OLD_DATA](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_OLD_DATA&type=code) | the TCP data reveived is already received before (spurious retrans may happened), see LINUX_MIB_DELAYEDACKLOST |
| [SKB_DROP_REASON_TCP_OVERWINDOW](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_OVERWINDOW&type=code) | the TCP data is out of window, the seq of the first byte exceed the right edges of receive window |
| [SKB_DROP_REASON_TCP_OFOMERGE](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_OFOMERGE&type=code) | the data of skb is already in the ofo queue, corresponding to LINUX_MIB_TCPOFOMERGE |
| [SKB_DROP_REASON_TCP_RFC7323_PAWS](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_RFC7323_PAWS&type=code) | PAWS check, corresponding to LINUX_MIB_PAWSESTABREJECTED |
| [SKB_DROP_REASON_TCP_INVALID_SEQUENCE](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_INVALID_SEQUENCE&type=code) | Not acceptable SEQ field |
| [SKB_DROP_REASON_TCP_RESET](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_RESET&type=code) | Invalid RST packet |
| [SKB_DROP_REASON_TCP_INVALID_SYN](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_INVALID_SYN&type=code) | Incoming packet has unexpected SYN flag |
| [SKB_DROP_REASON_TCP_CLOSE](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_CLOSE&type=code) | TCP socket in CLOSE state |
| [SKB_DROP_REASON_TCP_FASTOPEN](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_FASTOPEN&type=code) | dropped by FASTOPEN request socket |
| [SKB_DROP_REASON_TCP_OLD_ACK](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_OLD_ACK&type=code) | TCP ACK is old, but in window |
| [SKB_DROP_REASON_TCP_TOO_OLD_ACK](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_TOO_OLD_ACK&type=code) | TCP ACK is too old |
| [SKB_DROP_REASON_TCP_ACK_UNSENT_DATA](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_ACK_UNSENT_DATA&type=code) | TCP ACK for data we haven't sent yet |
| [SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_OFO_QUEUE_PRUNE&type=code) | pruned from TCP OFO queue |
| [SKB_DROP_REASON_TCP_OFO_DROP](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TCP_OFO_DROP&type=code) | data already in receive queue |
| [SKB_DROP_REASON_IP_OUTNOROUTES](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_OUTNOROUTES&type=code) | route lookup failed |
| [SKB_DROP_REASON_BPF_CGROUP_EGRESS](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_BPF_CGROUP_EGRESS&type=code) | dropped by BPF_PROG_TYPE_CGROUP_SKB eBPF program |
| [SKB_DROP_REASON_IPV6DISABLED](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IPV6DISABLED&type=code) | IPv6 is disabled on the device |
| [SKB_DROP_REASON_NEIGH_CREATEFAIL](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NEIGH_CREATEFAIL&type=code) | failed to create neigh entry |
| [SKB_DROP_REASON_NEIGH_FAILED](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NEIGH_FAILED&type=code) | neigh entry in failed state |
| [SKB_DROP_REASON_NEIGH_QUEUEFULL](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NEIGH_QUEUEFULL&type=code) | arp_queue for neigh entry is full |
| [SKB_DROP_REASON_NEIGH_DEAD](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NEIGH_DEAD&type=code) | neigh entry is dead |
| [SKB_DROP_REASON_TC_EGRESS](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TC_EGRESS&type=code) | dropped in TC egress HOOK |
| [SKB_DROP_REASON_QDISC_DROP](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_QDISC_DROP&type=code) | dropped by qdisc when packet outputting ( failed to enqueue to current qdisc) |
| [SKB_DROP_REASON_CPU_BACKLOG](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_CPU_BACKLOG&type=code) | failed to enqueue the skb to the per CPU backlog queue. This can be caused by backlog queue full (see netdev_max_backlog in net.rst) or RPS flow limit |
| [SKB_DROP_REASON_XDP](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_XDP&type=code) | dropped by XDP in input path |
| [SKB_DROP_REASON_TC_INGRESS](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TC_INGRESS&type=code) | dropped in TC ingress HOOK |
| [SKB_DROP_REASON_UNHANDLED_PROTO](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_UNHANDLED_PROTO&type=code) | protocol not implemented or not supported |
| [SKB_DROP_REASON_SKB_CSUM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_SKB_CSUM&type=code) | sk_buff checksum computation error |
| [SKB_DROP_REASON_SKB_GSO_SEG](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_SKB_GSO_SEG&type=code) | gso segmentation error |
| [SKB_DROP_REASON_SKB_UCOPY_FAULT](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_SKB_UCOPY_FAULT&type=code) | failed to copy data from user space, e.g., via zerocopy_sg_from_iter() or skb_orphan_frags_rx() |
| [SKB_DROP_REASON_DEV_HDR](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_DEV_HDR&type=code) | device driver specific header/metadata is invalid |
| [SKB_DROP_REASON_DEV_READY](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_DEV_READY&type=code) | the device is not ready to xmit/recv due to any of its data structure that is not up/ready/initialized, e.g., the IFF_UP is not set, or driver specific tun->tfiles[txq] is not initialized |
| [SKB_DROP_REASON_FULL_RING](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_FULL_RING&type=code) | ring buffer is full |
| [SKB_DROP_REASON_NOMEM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_NOMEM&type=code) | error due to OOM |
| [SKB_DROP_REASON_HDR_TRUNC](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_HDR_TRUNC&type=code) | failed to trunc/extract the header from networking data, e.g., failed to pull the protocol header from frags via pskb_may_pull() |
| [SKB_DROP_REASON_TAP_FILTER](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TAP_FILTER&type=code) | dropped by (ebpf) filter directly attached to tun/tap, e.g., via TUNSETFILTEREBPF |
| [SKB_DROP_REASON_TAP_TXFILTER](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_TAP_TXFILTER&type=code) | dropped by tx filter implemented at tun/tap, e.g., check_filter() |
| [SKB_DROP_REASON_ICMP_CSUM](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_ICMP_CSUM&type=code) | ICMP checksum error |
| [SKB_DROP_REASON_INVALID_PROTO](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_INVALID_PROTO&type=code) | the packet doesn't follow RFC 2211, such as a broadcasts ICMP_TIMESTAMP |
| [SKB_DROP_REASON_IP_INADDRERRORS](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_INADDRERRORS&type=code) | host unreachable, corresponding to IPSTATS_MIB_INADDRERRORS |
| [SKB_DROP_REASON_IP_INNOROUTES](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_IP_INNOROUTES&type=code) | network unreachable, corresponding to IPSTATS_MIB_INADDRERRORS |
| [SKB_DROP_REASON_PKT_TOO_BIG](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_PKT_TOO_BIG&type=code) | packet size is too big (maybe exceed the MTU) |
| [SKB_DROP_REASON_DUP_FRAG](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_DUP_FRAG&type=code) | duplicate fragment |
| [SKB_DROP_REASON_FRAG_REASM_TIMEOUT](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_FRAG_REASM_TIMEOUT&type=code) | fragment reassembly timeout |
| [SKB_DROP_REASON_FRAG_TOO_FAR](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_FRAG_TOO_FAR&type=code) | ipv4 fragment too far. (/proc/sys/net/ipv4/ipfrag_max_dist) |
| [SKB_DROP_REASON_MAX](https://github.com/search?q=repo%3Atorvalds%2Flinux%20SKB_DROP_REASON_MAX&type=code) | the maximum of drop reason, which shouldn't be used as a real 'reason' |

<!-- markdown-link-check-enable -->

This table can be generated with:

```bash
$ go run ./pkg/gadgets/trace/tcpdrop/tracer/dropreasongen/...
```

### Other tools showing dropped packets

The following tools can be used to show dropped packets but they are not focused on containers or Kubernetes:

* [dropwatch](https://github.com/nhorman/dropwatch): interactive tool using [Netlink Devlink Trap](https://www.kernel.org/doc/html/latest/networking/devlink/devlink-trap.html) to see drops packets by the NIC.
* [BCC's tcpdrop](https://github.com/iovisor/bcc/blob/master/tools/tcpdrop_example.txt): tool using eBPF and kprobes/tracepoints to show when a socket buffer is released by the kernel.
* [Retis' skb-drop collector](https://github.com/retis-org/retis): tool using various collectors (skb-drop, nftables, ovs) to show the flow of packets in the kernel.
