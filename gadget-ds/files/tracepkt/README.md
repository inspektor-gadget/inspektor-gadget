# tracepkt

tracepkt is available under the MIT license and comes from the following repository:
https://github.com/yadutaf/tracepkt

Inspiration:
- https://blog.yadutaf.fr/2017/07/28/tracing-a-packet-journey-using-linux-tracepoints-perf-ebpf/
- https://backreference.org/2010/06/11/iptables-debugging/

```
modprobe xt_TRACE
# for IPv4
iptables -t raw -A OUTPUT -p icmp -j TRACE
iptables -t raw -A PREROUTING -p icmp -j TRACE
# for IPv6
ip6tables -t raw -A OUTPUT -p icmpv6 --icmpv6-type echo-request -j TRACE
ip6tables -t raw -A OUTPUT -p icmpv6 --icmpv6-type echo-reply -j TRACE
ip6tables -t raw -A PREROUTING -p icmpv6 --icmpv6-type echo-request -j TRACE
ip6tables -t raw -A PREROUTING -p icmpv6 --icmpv6-type echo-reply -j TRACE
```

kprobe in `nf_log_trace`
