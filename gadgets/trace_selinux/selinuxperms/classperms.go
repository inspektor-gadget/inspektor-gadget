// Copyright 2026 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated from the Linux kernel security/selinux/include/classmap.h. DO NOT EDIT.

// Package selinuxperms maps SELinux object classes to their ordered
// access-vector permission names, used to decode AVC permission bitmasks.
package selinuxperms

// ClassPerms maps a SELinux object class to the ordered list of its
// access-vector permissions. The permission at index i corresponds to
// bit (1 << i) in the requested/denied/audited access-vector masks.
var ClassPerms = map[string][]string{
	"security":                      {"compute_av", "compute_create", "compute_member", "check_context", "load_policy", "compute_relabel", "compute_user", "setenforce", "setbool", "setsecparam", "setcheckreqprot", "read_policy", "validate_trans"},
	"process":                       {"fork", "transition", "sigchld", "sigkill", "sigstop", "signull", "signal", "ptrace", "getsched", "setsched", "getsession", "getpgid", "setpgid", "getcap", "setcap", "share", "getattr", "setexec", "setfscreate", "noatsecure", "siginh", "setrlimit", "rlimitinh", "dyntransition", "setcurrent", "execmem", "execstack", "execheap", "setkeycreate", "setsockcreate", "getrlimit"},
	"process2":                      {"nnp_transition", "nosuid_transition"},
	"system":                        {"ipc_info", "syslog_read", "syslog_mod", "syslog_console", "module_request", "module_load", "firmware_load", "kexec_image_load", "kexec_initramfs_load", "policy_load", "x509_certificate_load"},
	"capability":                    {"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap"},
	"filesystem":                    {"mount", "remount", "unmount", "getattr", "relabelfrom", "relabelto", "associate", "quotamod", "quotaget", "watch"},
	"file":                          {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns", "execute_no_trans", "entrypoint"},
	"dir":                           {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns", "add_name", "remove_name", "reparent", "search", "rmdir"},
	"fd":                            {"use"},
	"lnk_file":                      {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns"},
	"chr_file":                      {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns"},
	"blk_file":                      {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns"},
	"sock_file":                     {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns"},
	"fifo_file":                     {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns"},
	"socket":                        {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"tcp_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "node_bind", "name_connect"},
	"udp_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "node_bind"},
	"rawip_socket":                  {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "node_bind"},
	"node":                          {"recvfrom", "sendto"},
	"netif":                         {"ingress", "egress"},
	"netlink_socket":                {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"packet_socket":                 {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"key_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"unix_stream_socket":            {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "connectto"},
	"unix_dgram_socket":             {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"sem":                           {"create", "destroy", "getattr", "setattr", "read", "write", "associate", "unix_read", "unix_write"},
	"msg":                           {"send", "receive"},
	"msgq":                          {"create", "destroy", "getattr", "setattr", "read", "write", "associate", "unix_read", "unix_write", "enqueue"},
	"shm":                           {"create", "destroy", "getattr", "setattr", "read", "write", "associate", "unix_read", "unix_write", "lock"},
	"ipc":                           {"create", "destroy", "getattr", "setattr", "read", "write", "associate", "unix_read", "unix_write"},
	"netlink_route_socket":          {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "nlmsg_read", "nlmsg_write", "nlmsg"},
	"netlink_tcpdiag_socket":        {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "nlmsg_read", "nlmsg_write", "nlmsg"},
	"netlink_nflog_socket":          {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_xfrm_socket":           {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "nlmsg_read", "nlmsg_write", "nlmsg"},
	"netlink_selinux_socket":        {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_iscsi_socket":          {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_audit_socket":          {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "nlmsg_read", "nlmsg_write", "nlmsg_relay", "nlmsg_readpriv", "nlmsg_tty_audit", "nlmsg"},
	"netlink_fib_lookup_socket":     {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_connector_socket":      {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_netfilter_socket":      {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_dnrt_socket":           {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"association":                   {"sendto", "recvfrom", "setcontext", "polmatch"},
	"netlink_kobject_uevent_socket": {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_generic_socket":        {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_scsitransport_socket":  {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_rdma_socket":           {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netlink_crypto_socket":         {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"appletalk_socket":              {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"packet":                        {"send", "recv", "relabelto", "forward_in", "forward_out"},
	"key":                           {"view", "read", "write", "search", "link", "setattr", "create"},
	"memprotect":                    {"mmap_zero"},
	"peer":                          {"recv"},
	"capability2":                   {"mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"},
	"kernel_service":                {"use_as_override", "create_files_as"},
	"tun_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "attach_queue"},
	"binder":                        {"impersonate", "call", "set_context_mgr", "transfer"},
	"cap_userns":                    {"chown", "dac_override", "dac_read_search", "fowner", "fsetid", "kill", "setgid", "setuid", "setpcap", "linux_immutable", "net_bind_service", "net_broadcast", "net_admin", "net_raw", "ipc_lock", "ipc_owner", "sys_module", "sys_rawio", "sys_chroot", "sys_ptrace", "sys_pacct", "sys_admin", "sys_boot", "sys_nice", "sys_resource", "sys_time", "sys_tty_config", "mknod", "lease", "audit_write", "audit_control", "setfcap"},
	"cap2_userns":                   {"mac_override", "mac_admin", "syslog", "wake_alarm", "block_suspend", "audit_read", "perfmon", "bpf", "checkpoint_restore"},
	"sctp_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "node_bind", "name_connect", "association"},
	"icmp_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind", "node_bind"},
	"ax25_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"ipx_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"netrom_socket":                 {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"atmpvc_socket":                 {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"x25_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"rose_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"decnet_socket":                 {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"atmsvc_socket":                 {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"rds_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"irda_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"pppox_socket":                  {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"llc_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"can_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"tipc_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"bluetooth_socket":              {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"iucv_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"rxrpc_socket":                  {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"isdn_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"phonet_socket":                 {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"ieee802154_socket":             {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"caif_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"alg_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"nfc_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"vsock_socket":                  {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"kcm_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"qipcrtr_socket":                {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"smc_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"infiniband_pkey":               {"access"},
	"infiniband_endport":            {"manage_subnet"},
	"bpf":                           {"map_create", "map_read", "map_write", "prog_load", "prog_run", "map_create_as", "prog_load_as"},
	"xdp_socket":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"mctp_socket":                   {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "bind", "connect", "listen", "accept", "getopt", "setopt", "shutdown", "recvfrom", "sendto", "name_bind"},
	"perf_event":                    {"open", "cpu", "kernel", "tracepoint", "read", "write"},
	"anon_inode":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns"},
	"io_uring":                      {"override_creds", "sqpoll", "cmd", "allowed"},
	"user_namespace":                {"create"},
	"memfd_file":                    {"ioctl", "read", "write", "create", "getattr", "setattr", "lock", "relabelfrom", "relabelto", "append", "map", "unlink", "link", "rename", "execute", "quotaon", "mounton", "audit_access", "open", "execmod", "watch", "watch_mount", "watch_sb", "watch_with_perm", "watch_reads", "watch_mountns", "execute_no_trans", "entrypoint"},
}
