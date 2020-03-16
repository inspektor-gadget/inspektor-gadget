#!/usr/bin/env python
# coding: utf-8

import os
import sys
import json
from socket import inet_ntop, AF_INET, AF_INET6
from bcc import BPF
import ctypes as ct
import subprocess
from struct import pack

IFNAMSIZ = 16 # uapi/linux/if.h
XT_TABLE_MAXNAMELEN = 32 # uapi/linux/netfilter/x_tables.h

TABLENAMESIZ = 12
CHAINNAMESIZ = 16
COMMENTSIZ = 8

# uapi/linux/netfilter.h
NF_VERDICT_NAME = [
    'DROP',
    'ACCEPT',
    'STOLEN',
    'QUEUE',
    'REPEAT',
    'STOP',
]

# uapi/linux/netfilter.h
# net/ipv4/netfilter/ip_tables.c
HOOKNAMES = [
    "PREROUTING",
    "INPUT",
    "FORWARD",
    "OUTPUT",
    "POSTROUTING",
]

ROUTE_EVT_IF = 1
ROUTE_EVT_IPTABLE = 2
ROUTE_EVT_IPTABLE_STEP = 4

class TestEvt(ct.Structure):
    _fields_ = [
        # Content flags
        ("flags",   ct.c_ulonglong),

        # Routing information
        ("ifname",  ct.c_char * IFNAMSIZ),
        ("netns",   ct.c_ulonglong),

        # Packet type (IPv4 or IPv6) and address
        ("ip_version",  ct.c_ulonglong),
        ("icmptype",    ct.c_ulonglong),
        ("icmpid",      ct.c_ulonglong),
        ("icmpseq",     ct.c_ulonglong),
        ("icmppad",     ct.c_ulonglong),
        ("saddr",       ct.c_ulonglong * 2),
        ("daddr",       ct.c_ulonglong * 2),

        # Iptables trace
        ("hook",        ct.c_ulonglong),
        ("verdict",     ct.c_ulonglong),
        ("tablename",   ct.c_char * XT_TABLE_MAXNAMELEN),

        # Iptables step trace
        ("ifname_in",                 ct.c_char * IFNAMSIZ),
        ("ifname_out",                ct.c_char * IFNAMSIZ),
        ("iptables_step_tablename",   ct.c_char * TABLENAMESIZ),
        ("iptables_step_chainname",   ct.c_char * CHAINNAMESIZ),
        ("iptables_step_comment",     ct.c_char * COMMENTSIZ),
        ("iptables_step_rulenum",     ct.c_ulonglong),
    ]

PING_PID="-1"
# Network endianness, as "ping -p" expects it
PING_PAD_STR="11223344aabbccdd"
# CPU endianness
PING_PAD=0xddccbbaa44332211

def _get(l, index, default):
    '''
    Get element at index in l or return the default
    '''
    if index < len(l):
        return l[index]
    return default

def event_printer(cpu, data, size):
    # Decode event
    event = ct.cast(data, ct.POINTER(TestEvt)).contents
    event_dict = dict((field, getattr(event, field)) for field, _ in TestEvt._fields_ if not field.endswith('addr') )

    # Make sure this is an interface event
    if event.flags & ROUTE_EVT_IF != ROUTE_EVT_IF:
        return

    # Make sure it is OUR ping process
    # Warning: icmpid is no longer the pid: https://github.com/iputils/iputils/commit/5026c2221a15bf13e601eade015c971bf07a27e9
    if event.icmppad != PING_PAD:
        return

    # Decode address
    if event.ip_version == 4:
        saddr = inet_ntop(AF_INET, pack("=I", event.saddr[0]))
        daddr = inet_ntop(AF_INET, pack("=I", event.daddr[0]))
    elif event.ip_version == 6:
        saddr = inet_ntop(AF_INET6, event.saddr)
        daddr = inet_ntop(AF_INET6, event.daddr)
    else:
        return
    event_dict["saddr"] = saddr
    event_dict["daddr"] = daddr

    # Decode direction
    if event.icmptype in [8, 128]:
        direction = "request"
    elif event.icmptype in [0, 129]:
        direction = "reply"
    else:
        return
    event_dict["direction"] = direction

    # Decode flow
    flow = "%s -> %s" % (saddr, daddr)

    event_dict["kind"] = "unknown"
    if event.flags & ROUTE_EVT_IF == ROUTE_EVT_IF:
        event_dict["kind"] += "packet"
    if event.flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE:
        event_dict["kind"] += "iptable"
    if event.flags & ROUTE_EVT_IPTABLE_STEP == ROUTE_EVT_IPTABLE_STEP:
        event_dict["kind"] += "iptable-step"

    # Optionally decode iptables events
    if event.flags & ROUTE_EVT_IPTABLE == ROUTE_EVT_IPTABLE:
        verdict = _get(NF_VERDICT_NAME, event.verdict, "~UNK~")
        hook = _get(HOOKNAMES, event.hook, "~UNK~")

        event_dict["verdict"] = verdict
        event_dict["hook"] = hook
    else:
        event_dict["verdict"] = ""
        event_dict["hook"] = ""

    # Print event
    print json.dumps(event_dict)

if __name__ == "__main__":
    # Get arguments
    if len(sys.argv) == 1:
        TARGET = None
        NSENTER = None
    elif len(sys.argv) == 2:
        TARGET = sys.argv[1]
        NSENTER = ''
    elif len(sys.argv) == 3:
        TARGET = sys.argv[1]
        NSENTER = 'nsenter -n -t $(chroot /host docker inspect %s --format "{{.State.Pid}}")' %(sys.argv[2])
    else:
        print "Usage: %s [TARGET_IP] [SOURCE]" % (sys.argv[0])
        sys.exit(1)

    # Load kernel modules if needed
    os.system("""
        chroot /host modprobe ip6_tables ;
        chroot /host modprobe xt_TRACE ;
        chroot /host iptables -t raw -A OUTPUT -p icmp -j TRACE ;
        chroot /host iptables -t raw -A PREROUTING -p icmp -j TRACE ;
        chroot /host ip6tables -t raw -A OUTPUT -p icmpv6 --icmpv6-type echo-request -j TRACE ;
        chroot /host ip6tables -t raw -A OUTPUT -p icmpv6 --icmpv6-type echo-reply -j TRACE ;
        chroot /host ip6tables -t raw -A PREROUTING -p icmpv6 --icmpv6-type echo-request -j TRACE ;
        chroot /host ip6tables -t raw -A PREROUTING -p icmpv6 --icmpv6-type echo-reply -j TRACE
    """)

    # Build probe and open event buffer
    b = BPF(src_file='tracepkt.c')
    b["route_evt"].open_perf_buffer(event_printer)

    # Launch a background ping process
    if TARGET is not None:
        with open('/dev/null', 'r') as devnull:
            ping = subprocess.Popen([
                    '/bin/sh', '-c',
                    NSENTER + ' ping -c1 -p' + PING_PAD_STR + ' ' + TARGET,
                ],
                stdout=devnull,
                stderr=devnull,
                close_fds=True,
            )
        PING_PID = ping.pid

    if TARGET is not None:
        # Listen for event until the ping process has exited
        while ping.poll() is None:
            b.perf_buffer_poll(50)
        ## Forward ping's exit code
        #sys.exit(ping.poll())
    else:
        while 1:
            try:
                b.perf_buffer_poll()
            except KeyboardInterrupt:
                exit();

        #sys.exit(0)

    os.system("""
        chroot /host iptables -t raw -D OUTPUT -p icmp -j TRACE ;
        chroot /host iptables -t raw -D PREROUTING -p icmp -j TRACE ;
        chroot /host ip6tables -t raw -D OUTPUT -p icmpv6 --icmpv6-type echo-request -j TRACE ;
        chroot /host ip6tables -t raw -D OUTPUT -p icmpv6 --icmpv6-type echo-reply -j TRACE ;
        chroot /host ip6tables -t raw -D PREROUTING -p icmpv6 --icmpv6-type echo-request -j TRACE ;
        chroot /host ip6tables -t raw -D PREROUTING -p icmpv6 --icmpv6-type echo-reply -j TRACE
    """)

    sys.exit(0)
