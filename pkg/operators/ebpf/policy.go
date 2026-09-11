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

package ebpfoperator

import (
	"fmt"
	"maps"
	"sort"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/asm"
)

// verifyCollectionSpec checks the gadget's final instructions, including linked subprograms.
func verifyCollectionSpec(spec *ebpf.CollectionSpec, p *policy) error {
	if p == nil || (p.helpers.unrestricted() && p.programTypes.unrestricted()) {
		return nil
	}
	var violations []string
	for name, prog := range spec.Programs {
		if !p.programTypes.allows(prog.Type) {
			violations = append(violations, fmt.Sprintf("program %q uses denied BPF program type %q", name, programTypeToName(prog.Type)))
		}
		if p.helpers.unrestricted() {
			continue
		}
		helpers := extractHelpers(prog)
		for h := range helpers {
			if !p.helpers.allows(h) {
				violations = append(violations, fmt.Sprintf("program %q uses denied BPF helper %q", name, helperFuncToName(h)))
			}
			var fallback asm.BuiltinFunc
			switch h {
			case asm.FnProbeReadKernel, asm.FnProbeReadUser:
				fallback = asm.FnProbeRead
			case asm.FnProbeReadKernelStr, asm.FnProbeReadUserStr:
				fallback = asm.FnProbeReadStr
			}
			if fallback != 0 && !p.helpers.allows(fallback) {
				violations = append(violations, fmt.Sprintf("program %q helper %q requires denied loader fallback helper %q", name, helperFuncToName(h), helperFuncToName(fallback)))
			}
		}
		if p.readonlyHelpers {
			for _, ins := range prog.Instructions {
				if ins.IsKfuncCall() {
					violations = append(violations, fmt.Sprintf("program %q uses a kfunc call denied by helpers readonly", name))
					break
				}
			}
		}
	}
	if len(violations) == 0 {
		return nil
	}
	sort.Strings(violations)
	return fmt.Errorf("BPF policy violations:\n%s", strings.Join(violations, "\n"))
}

// helperNameToID maps BPF helper names to their function IDs.
// Names use the standard bpf_foo_bar format (with the bpf_ prefix in the key).
// Based on Linux kernel's include/uapi/linux/bpf.h
var helperNameToID = map[string]asm.BuiltinFunc{
	"bpf_map_lookup_elem":                asm.FnMapLookupElem,
	"bpf_map_update_elem":                asm.FnMapUpdateElem,
	"bpf_map_delete_elem":                asm.FnMapDeleteElem,
	"bpf_probe_read":                     asm.FnProbeRead,
	"bpf_ktime_get_ns":                   asm.FnKtimeGetNs,
	"bpf_trace_printk":                   asm.FnTracePrintk,
	"bpf_get_prandom_u32":                asm.FnGetPrandomU32,
	"bpf_get_smp_processor_id":           asm.FnGetSmpProcessorId,
	"bpf_skb_store_bytes":                asm.FnSkbStoreBytes,
	"bpf_l3_csum_replace":                asm.FnL3CsumReplace,
	"bpf_l4_csum_replace":                asm.FnL4CsumReplace,
	"bpf_tail_call":                      asm.FnTailCall,
	"bpf_clone_redirect":                 asm.FnCloneRedirect,
	"bpf_get_current_pid_tgid":           asm.FnGetCurrentPidTgid,
	"bpf_get_current_uid_gid":            asm.FnGetCurrentUidGid,
	"bpf_get_current_comm":               asm.FnGetCurrentComm,
	"bpf_get_cgroup_classid":             asm.FnGetCgroupClassid,
	"bpf_skb_vlan_push":                  asm.FnSkbVlanPush,
	"bpf_skb_vlan_pop":                   asm.FnSkbVlanPop,
	"bpf_skb_get_tunnel_key":             asm.FnSkbGetTunnelKey,
	"bpf_skb_set_tunnel_key":             asm.FnSkbSetTunnelKey,
	"bpf_perf_event_read":                asm.FnPerfEventRead,
	"bpf_redirect":                       asm.FnRedirect,
	"bpf_get_route_realm":                asm.FnGetRouteRealm,
	"bpf_perf_event_output":              asm.FnPerfEventOutput,
	"bpf_skb_load_bytes":                 asm.FnSkbLoadBytes,
	"bpf_get_stackid":                    asm.FnGetStackid,
	"bpf_csum_diff":                      asm.FnCsumDiff,
	"bpf_skb_get_tunnel_opt":             asm.FnSkbGetTunnelOpt,
	"bpf_skb_set_tunnel_opt":             asm.FnSkbSetTunnelOpt,
	"bpf_skb_change_proto":               asm.FnSkbChangeProto,
	"bpf_skb_change_type":                asm.FnSkbChangeType,
	"bpf_skb_under_cgroup":               asm.FnSkbUnderCgroup,
	"bpf_get_hash_recalc":                asm.FnGetHashRecalc,
	"bpf_get_current_task":               asm.FnGetCurrentTask,
	"bpf_probe_write_user":               asm.FnProbeWriteUser,
	"bpf_current_task_under_cgroup":      asm.FnCurrentTaskUnderCgroup,
	"bpf_skb_change_tail":                asm.FnSkbChangeTail,
	"bpf_skb_pull_data":                  asm.FnSkbPullData,
	"bpf_csum_update":                    asm.FnCsumUpdate,
	"bpf_set_hash_invalid":               asm.FnSetHashInvalid,
	"bpf_get_numa_node_id":               asm.FnGetNumaNodeId,
	"bpf_skb_change_head":                asm.FnSkbChangeHead,
	"bpf_xdp_adjust_head":                asm.FnXdpAdjustHead,
	"bpf_probe_read_str":                 asm.FnProbeReadStr,
	"bpf_get_socket_cookie":              asm.FnGetSocketCookie,
	"bpf_get_socket_uid":                 asm.FnGetSocketUid,
	"bpf_set_hash":                       asm.FnSetHash,
	"bpf_setsockopt":                     asm.FnSetsockopt,
	"bpf_skb_adjust_room":                asm.FnSkbAdjustRoom,
	"bpf_redirect_map":                   asm.FnRedirectMap,
	"bpf_sk_redirect_map":                asm.FnSkRedirectMap,
	"bpf_sock_map_update":                asm.FnSockMapUpdate,
	"bpf_xdp_adjust_meta":                asm.FnXdpAdjustMeta,
	"bpf_perf_event_read_value":          asm.FnPerfEventReadValue,
	"bpf_perf_prog_read_value":           asm.FnPerfProgReadValue,
	"bpf_getsockopt":                     asm.FnGetsockopt,
	"bpf_override_return":                asm.FnOverrideReturn,
	"bpf_sock_ops_cb_flags_set":          asm.FnSockOpsCbFlagsSet,
	"bpf_msg_redirect_map":               asm.FnMsgRedirectMap,
	"bpf_msg_apply_bytes":                asm.FnMsgApplyBytes,
	"bpf_msg_cork_bytes":                 asm.FnMsgCorkBytes,
	"bpf_msg_pull_data":                  asm.FnMsgPullData,
	"bpf_bind":                           asm.FnBind,
	"bpf_xdp_adjust_tail":                asm.FnXdpAdjustTail,
	"bpf_skb_get_xfrm_state":             asm.FnSkbGetXfrmState,
	"bpf_get_stack":                      asm.FnGetStack,
	"bpf_skb_load_bytes_relative":        asm.FnSkbLoadBytesRelative,
	"bpf_fib_lookup":                     asm.FnFibLookup,
	"bpf_sock_hash_update":               asm.FnSockHashUpdate,
	"bpf_msg_redirect_hash":              asm.FnMsgRedirectHash,
	"bpf_sk_redirect_hash":               asm.FnSkRedirectHash,
	"bpf_lwt_push_encap":                 asm.FnLwtPushEncap,
	"bpf_lwt_seg6_store_bytes":           asm.FnLwtSeg6StoreBytes,
	"bpf_lwt_seg6_adjust_srh":            asm.FnLwtSeg6AdjustSrh,
	"bpf_lwt_seg6_action":                asm.FnLwtSeg6Action,
	"bpf_rc_repeat":                      asm.FnRcRepeat,
	"bpf_rc_keydown":                     asm.FnRcKeydown,
	"bpf_skb_cgroup_id":                  asm.FnSkbCgroupId,
	"bpf_get_current_cgroup_id":          asm.FnGetCurrentCgroupId,
	"bpf_get_local_storage":              asm.FnGetLocalStorage,
	"bpf_sk_select_reuseport":            asm.FnSkSelectReuseport,
	"bpf_skb_ancestor_cgroup_id":         asm.FnSkbAncestorCgroupId,
	"bpf_sk_lookup_tcp":                  asm.FnSkLookupTcp,
	"bpf_sk_lookup_udp":                  asm.FnSkLookupUdp,
	"bpf_sk_release":                     asm.FnSkRelease,
	"bpf_map_push_elem":                  asm.FnMapPushElem,
	"bpf_map_pop_elem":                   asm.FnMapPopElem,
	"bpf_map_peek_elem":                  asm.FnMapPeekElem,
	"bpf_msg_push_data":                  asm.FnMsgPushData,
	"bpf_msg_pop_data":                   asm.FnMsgPopData,
	"bpf_rc_pointer_rel":                 asm.FnRcPointerRel,
	"bpf_spin_lock":                      asm.FnSpinLock,
	"bpf_spin_unlock":                    asm.FnSpinUnlock,
	"bpf_sk_fullsock":                    asm.FnSkFullsock,
	"bpf_tcp_sock":                       asm.FnTcpSock,
	"bpf_skb_ecn_set_ce":                 asm.FnSkbEcnSetCe,
	"bpf_get_listener_sock":              asm.FnGetListenerSock,
	"bpf_skc_lookup_tcp":                 asm.FnSkcLookupTcp,
	"bpf_tcp_check_syncookie":            asm.FnTcpCheckSyncookie,
	"bpf_sysctl_get_name":                asm.FnSysctlGetName,
	"bpf_sysctl_get_current_value":       asm.FnSysctlGetCurrentValue,
	"bpf_sysctl_get_new_value":           asm.FnSysctlGetNewValue,
	"bpf_sysctl_set_new_value":           asm.FnSysctlSetNewValue,
	"bpf_strtol":                         asm.FnStrtol,
	"bpf_strtoul":                        asm.FnStrtoul,
	"bpf_sk_storage_get":                 asm.FnSkStorageGet,
	"bpf_sk_storage_delete":              asm.FnSkStorageDelete,
	"bpf_send_signal":                    asm.FnSendSignal,
	"bpf_tcp_gen_syncookie":              asm.FnTcpGenSyncookie,
	"bpf_skb_output":                     asm.FnSkbOutput,
	"bpf_probe_read_user":                asm.FnProbeReadUser,
	"bpf_probe_read_kernel":              asm.FnProbeReadKernel,
	"bpf_probe_read_user_str":            asm.FnProbeReadUserStr,
	"bpf_probe_read_kernel_str":          asm.FnProbeReadKernelStr,
	"bpf_tcp_send_ack":                   asm.FnTcpSendAck,
	"bpf_send_signal_thread":             asm.FnSendSignalThread,
	"bpf_jiffies64":                      asm.FnJiffies64,
	"bpf_read_branch_records":            asm.FnReadBranchRecords,
	"bpf_get_ns_current_pid_tgid":        asm.FnGetNsCurrentPidTgid,
	"bpf_xdp_output":                     asm.FnXdpOutput,
	"bpf_get_netns_cookie":               asm.FnGetNetnsCookie,
	"bpf_get_current_ancestor_cgroup_id": asm.FnGetCurrentAncestorCgroupId,
	"bpf_sk_assign":                      asm.FnSkAssign,
	"bpf_ktime_get_boot_ns":              asm.FnKtimeGetBootNs,
	"bpf_seq_printf":                     asm.FnSeqPrintf,
	"bpf_seq_write":                      asm.FnSeqWrite,
	"bpf_sk_cgroup_id":                   asm.FnSkCgroupId,
	"bpf_sk_ancestor_cgroup_id":          asm.FnSkAncestorCgroupId,
	"bpf_ringbuf_output":                 asm.FnRingbufOutput,
	"bpf_ringbuf_reserve":                asm.FnRingbufReserve,
	"bpf_ringbuf_submit":                 asm.FnRingbufSubmit,
	"bpf_ringbuf_discard":                asm.FnRingbufDiscard,
	"bpf_ringbuf_query":                  asm.FnRingbufQuery,
	"bpf_csum_level":                     asm.FnCsumLevel,
	"bpf_skc_to_tcp6_sock":               asm.FnSkcToTcp6Sock,
	"bpf_skc_to_tcp_sock":                asm.FnSkcToTcpSock,
	"bpf_skc_to_tcp_timewait_sock":       asm.FnSkcToTcpTimewaitSock,
	"bpf_skc_to_tcp_request_sock":        asm.FnSkcToTcpRequestSock,
	"bpf_skc_to_udp6_sock":               asm.FnSkcToUdp6Sock,
	"bpf_get_task_stack":                 asm.FnGetTaskStack,
	"bpf_load_hdr_opt":                   asm.FnLoadHdrOpt,
	"bpf_store_hdr_opt":                  asm.FnStoreHdrOpt,
	"bpf_reserve_hdr_opt":                asm.FnReserveHdrOpt,
	"bpf_inode_storage_get":              asm.FnInodeStorageGet,
	"bpf_inode_storage_delete":           asm.FnInodeStorageDelete,
	"bpf_d_path":                         asm.FnDPath,
	"bpf_copy_from_user":                 asm.FnCopyFromUser,
	"bpf_snprintf_btf":                   asm.FnSnprintfBtf,
	"bpf_seq_printf_btf":                 asm.FnSeqPrintfBtf,
	"bpf_skb_cgroup_classid":             asm.FnSkbCgroupClassid,
	"bpf_redirect_neigh":                 asm.FnRedirectNeigh,
	"bpf_per_cpu_ptr":                    asm.FnPerCpuPtr,
	"bpf_this_cpu_ptr":                   asm.FnThisCpuPtr,
	"bpf_redirect_peer":                  asm.FnRedirectPeer,
	"bpf_task_storage_get":               asm.FnTaskStorageGet,
	"bpf_task_storage_delete":            asm.FnTaskStorageDelete,
	"bpf_get_current_task_btf":           asm.FnGetCurrentTaskBtf,
	"bpf_bprm_opts_set":                  asm.FnBprmOptsSet,
	"bpf_ktime_get_coarse_ns":            asm.FnKtimeGetCoarseNs,
	"bpf_ima_inode_hash":                 asm.FnImaInodeHash,
	"bpf_sock_from_file":                 asm.FnSockFromFile,
	"bpf_check_mtu":                      asm.FnCheckMtu,
	"bpf_for_each_map_elem":              asm.FnForEachMapElem,
	"bpf_snprintf":                       asm.FnSnprintf,
	"bpf_sys_bpf":                        asm.FnSysBpf,
	"bpf_btf_find_by_name_kind":          asm.FnBtfFindByNameKind,
	"bpf_sys_close":                      asm.FnSysClose,
	"bpf_timer_init":                     asm.FnTimerInit,
	"bpf_timer_set_callback":             asm.FnTimerSetCallback,
	"bpf_timer_start":                    asm.FnTimerStart,
	"bpf_timer_cancel":                   asm.FnTimerCancel,
	"bpf_get_func_ip":                    asm.FnGetFuncIp,
	"bpf_get_attach_cookie":              asm.FnGetAttachCookie,
	"bpf_task_pt_regs":                   asm.FnTaskPtRegs,
	"bpf_get_branch_snapshot":            asm.FnGetBranchSnapshot,
	"bpf_trace_vprintk":                  asm.FnTraceVprintk,
	"bpf_skc_to_unix_sock":               asm.FnSkcToUnixSock,
	"bpf_kallsyms_lookup_name":           asm.FnKallsymsLookupName,
	"bpf_find_vma":                       asm.FnFindVma,
	"bpf_loop":                           asm.FnLoop,
	"bpf_strncmp":                        asm.FnStrncmp,
	"bpf_get_func_arg":                   asm.FnGetFuncArg,
	"bpf_get_func_ret":                   asm.FnGetFuncRet,
	"bpf_get_func_arg_cnt":               asm.FnGetFuncArgCnt,
	"bpf_get_retval":                     asm.FnGetRetval,
	"bpf_set_retval":                     asm.FnSetRetval,
	"bpf_xdp_get_buff_len":               asm.FnXdpGetBuffLen,
	"bpf_xdp_load_bytes":                 asm.FnXdpLoadBytes,
	"bpf_xdp_store_bytes":                asm.FnXdpStoreBytes,
	"bpf_copy_from_user_task":            asm.FnCopyFromUserTask,
	"bpf_skb_set_tstamp":                 asm.FnSkbSetTstamp,
	"bpf_ima_file_hash":                  asm.FnImaFileHash,
	"bpf_kptr_xchg":                      asm.FnKptrXchg,
	"bpf_map_lookup_percpu_elem":         asm.FnMapLookupPercpuElem,
	"bpf_skc_to_mptcp_sock":              asm.FnSkcToMptcpSock,
	"bpf_dynptr_from_mem":                asm.FnDynptrFromMem,
	"bpf_ringbuf_reserve_dynptr":         asm.FnRingbufReserveDynptr,
	"bpf_ringbuf_submit_dynptr":          asm.FnRingbufSubmitDynptr,
	"bpf_ringbuf_discard_dynptr":         asm.FnRingbufDiscardDynptr,
	"bpf_dynptr_read":                    asm.FnDynptrRead,
	"bpf_dynptr_write":                   asm.FnDynptrWrite,
	"bpf_dynptr_data":                    asm.FnDynptrData,
	"bpf_tcp_raw_gen_syncookie_ipv4":     asm.FnTcpRawGenSyncookieIpv4,
	"bpf_tcp_raw_gen_syncookie_ipv6":     asm.FnTcpRawGenSyncookieIpv6,
	"bpf_tcp_raw_check_syncookie_ipv4":   asm.FnTcpRawCheckSyncookieIpv4,
	"bpf_tcp_raw_check_syncookie_ipv6":   asm.FnTcpRawCheckSyncookieIpv6,
	"bpf_ktime_get_tai_ns":               asm.FnKtimeGetTaiNs,
	"bpf_user_ringbuf_drain":             asm.FnUserRingbufDrain,
	"bpf_cgrp_storage_get":               asm.FnCgrpStorageGet,
	"bpf_cgrp_storage_delete":            asm.FnCgrpStorageDelete,
}

// programTypeNameToID maps user-friendly BPF program type names to their IDs.
// Names use lowercase format (e.g., "kprobe", "tracepoint").
var programTypeNameToID = map[string]ebpf.ProgramType{
	"unspec":                  ebpf.UnspecifiedProgram,
	"socket_filter":           ebpf.SocketFilter,
	"kprobe":                  ebpf.Kprobe,
	"sched_cls":               ebpf.SchedCLS,
	"sched_act":               ebpf.SchedACT,
	"tracepoint":              ebpf.TracePoint,
	"xdp":                     ebpf.XDP,
	"perf_event":              ebpf.PerfEvent,
	"cgroup_skb":              ebpf.CGroupSKB,
	"cgroup_sock":             ebpf.CGroupSock,
	"lwt_in":                  ebpf.LWTIn,
	"lwt_out":                 ebpf.LWTOut,
	"lwt_xmit":                ebpf.LWTXmit,
	"sock_ops":                ebpf.SockOps,
	"sk_skb":                  ebpf.SkSKB,
	"cgroup_device":           ebpf.CGroupDevice,
	"sk_msg":                  ebpf.SkMsg,
	"raw_tracepoint":          ebpf.RawTracepoint,
	"cgroup_sock_addr":        ebpf.CGroupSockAddr,
	"lwt_seg6local":           ebpf.LWTSeg6Local,
	"lirc_mode2":              ebpf.LircMode2,
	"sk_reuseport":            ebpf.SkReuseport,
	"flow_dissector":          ebpf.FlowDissector,
	"cgroup_sysctl":           ebpf.CGroupSysctl,
	"raw_tracepoint_writable": ebpf.RawTracepointWritable,
	"cgroup_sockopt":          ebpf.CGroupSockopt,
	"tracing":                 ebpf.Tracing,
	"struct_ops":              ebpf.StructOps,
	"ext":                     ebpf.Extension,
	"extension":               ebpf.Extension,
	"lsm":                     ebpf.LSM,
	"sk_lookup":               ebpf.SkLookup,
	"syscall":                 ebpf.Syscall,
	"netfilter":               ebpf.Netfilter,
}

// helperIDToName maps BPF helper function IDs to their names.
var helperIDToName []string

// programTypeIDToName maps BPF program type IDs to their names.
var programTypeIDToName []string

func init() {
	// Helper IDs are continuous starting from 0, so we can use map length directly
	helperIDToName = make([]string, len(helperNameToID)+1)
	for name, id := range helperNameToID {
		helperIDToName[id] = name
	}

	// Program type IDs are continuous starting from 0, so we can use map length directly
	programTypeIDToName = make([]string, len(programTypeNameToID)+1)
	for name, id := range programTypeNameToID {
		if programTypeIDToName[id] == "" || name < programTypeIDToName[id] {
			programTypeIDToName[id] = name
		}
	}
}

// helperNameToFunc converts a user-friendly BPF helper name to its function ID.
// It accepts the standard BPF helper name format (e.g., "bpf_map_lookup_elem").
// The "bpf_" prefix is required.
func helperNameToFunc(s string) (asm.BuiltinFunc, error) {
	if id, ok := helperNameToID[strings.ToLower(strings.TrimSpace(s))]; ok {
		return id, nil
	}

	return 0, fmt.Errorf("unknown BPF helper: %q", s)
}

// helperFuncToName converts a BPF helper function ID to its user-friendly name.
func helperFuncToName(h asm.BuiltinFunc) string {
	if uint64(h) < uint64(len(helperIDToName)) && helperIDToName[h] != "" {
		return helperIDToName[h]
	}
	return fmt.Sprintf("bpf_unknown_%d", h)
}

// programTypeNameToType converts a user-friendly BPF program type name to ebpf.ProgramType.
// It accepts various common formats (e.g., "kprobe", "KPROBE", "BPF_PROG_TYPE_KPROBE").
func programTypeNameToType(s string) (ebpf.ProgramType, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, fmt.Errorf("empty program type name")
	}

	// Normalize: remove BPF_PROG_TYPE_ prefix if present, convert to lowercase
	normalized := strings.ToLower(strings.TrimPrefix(strings.ToUpper(s), "BPF_PROG_TYPE_"))

	if pt, ok := programTypeNameToID[normalized]; ok {
		return pt, nil
	}

	return 0, fmt.Errorf("unknown BPF program type: %q", s)
}

// programTypeToName converts an ebpf.ProgramType to its user-friendly name.
func programTypeToName(pt ebpf.ProgramType) string {
	if uint64(pt) < uint64(len(programTypeIDToName)) && programTypeIDToName[pt] != "" {
		return programTypeIDToName[pt]
	}
	return fmt.Sprintf("unknown_prog_type_%d", pt)
}

// readonlyHelpers is a curated observability selection, not a sandbox.
// Map writes, output, and access to sensitive data are intentionally possible.
var readonlyHelpers = map[asm.BuiltinFunc]struct{}{
	// Map operations
	asm.FnMapLookupElem:       {},
	asm.FnMapUpdateElem:       {},
	asm.FnMapDeleteElem:       {},
	asm.FnMapPushElem:         {},
	asm.FnMapPopElem:          {},
	asm.FnMapPeekElem:         {},
	asm.FnMapLookupPercpuElem: {},
	asm.FnForEachMapElem:      {},

	// Ring buffer operations
	asm.FnRingbufOutput:        {},
	asm.FnRingbufReserve:       {},
	asm.FnRingbufSubmit:        {},
	asm.FnRingbufDiscard:       {},
	asm.FnRingbufQuery:         {},
	asm.FnRingbufReserveDynptr: {},
	asm.FnRingbufSubmitDynptr:  {},
	asm.FnRingbufDiscardDynptr: {},

	// Perf event operations
	asm.FnPerfEventOutput:    {},
	asm.FnPerfEventRead:      {},
	asm.FnPerfEventReadValue: {},

	// Process/task information
	asm.FnGetCurrentPidTgid:          {},
	asm.FnGetCurrentUidGid:           {},
	asm.FnGetCurrentComm:             {},
	asm.FnGetCurrentTask:             {},
	asm.FnGetCurrentTaskBtf:          {},
	asm.FnGetCurrentCgroupId:         {},
	asm.FnGetCurrentAncestorCgroupId: {},
	asm.FnGetNsCurrentPidTgid:        {},
	asm.FnTaskPtRegs:                 {},

	// Time operations
	asm.FnKtimeGetNs:       {},
	asm.FnKtimeGetBootNs:   {},
	asm.FnKtimeGetCoarseNs: {},
	asm.FnKtimeGetTaiNs:    {},
	asm.FnJiffies64:        {},

	// Memory operations
	asm.FnProbeRead:          {},
	asm.FnProbeReadStr:       {},
	asm.FnProbeReadUser:      {},
	asm.FnProbeReadUserStr:   {},
	asm.FnProbeReadKernel:    {},
	asm.FnProbeReadKernelStr: {},
	asm.FnCopyFromUser:       {},
	asm.FnCopyFromUserTask:   {},

	// Stack traces
	asm.FnGetStackid: {},
	asm.FnGetStack:   {},

	// Random numbers
	asm.FnGetPrandomU32: {},

	// CPU information
	asm.FnGetSmpProcessorId: {},
	asm.FnGetNumaNodeId:     {},

	// Cgroup operations
	asm.FnGetCgroupClassid:    {},
	asm.FnSkbCgroupClassid:    {},
	asm.FnSkbAncestorCgroupId: {},
	asm.FnSkAncestorCgroupId:  {},
	asm.FnSkCgroupId:          {},

	// Socket inspection (may acquire references or initialize a socket cookie)
	asm.FnGetSocketCookie: {},
	asm.FnGetSocketUid:    {},
	asm.FnSkLookupTcp:     {},
	asm.FnSkLookupUdp:     {},
	asm.FnSkRelease:       {},
	asm.FnSkFullsock:      {},
	asm.FnGetListenerSock: {},

	// Network helpers (read-only)
	asm.FnSkbLoadBytes:         {},
	asm.FnSkbLoadBytesRelative: {},
	asm.FnGetRouteRealm:        {},
	asm.FnSkbUnderCgroup:       {},

	// Tracing/printing helpers
	asm.FnTracePrintk:  {},
	asm.FnSnprintf:     {},
	asm.FnSnprintfBtf:  {},
	asm.FnSeqPrintf:    {},
	asm.FnSeqWrite:     {},
	asm.FnSeqPrintfBtf: {},

	// Function arguments (tracing)
	asm.FnGetFuncIp:         {},
	asm.FnGetAttachCookie:   {},
	asm.FnGetFuncArgCnt:     {},
	asm.FnGetFuncArg:        {},
	asm.FnGetFuncRet:        {},
	asm.FnGetRetval:         {},
	asm.FnGetBranchSnapshot: {},

	// Spin locks (for map synchronization)
	asm.FnSpinLock:   {},
	asm.FnSpinUnlock: {},

	// Task/process lookup
	asm.FnFindVma: {},

	// Inode/path helpers
	asm.FnDPath: {},

	// Per-CPU data
	asm.FnPerCpuPtr:  {},
	asm.FnThisCpuPtr: {},

	// Dynptr operations
	asm.FnDynptrData:       {},
	asm.FnDynptrFromMem:    {},
	asm.FnDynptrRead:       {},
	asm.FnUserRingbufDrain: {},

	// Tail calls (external targets are outside this policy)
	asm.FnTailCall: {},
}

// readonlyProgramTypes excludes types whose return values or attach modes can
// directly influence system behavior. Helper readonly must be selected separately.
var readonlyProgramTypes = map[ebpf.ProgramType]struct{}{
	ebpf.Kprobe: {}, ebpf.TracePoint: {}, ebpf.RawTracepoint: {}, ebpf.PerfEvent: {},
}

// validateKeywords checks for special keywords ("all" or "readonly")
// Returns error if both keywords are used together or if a keyword is used with other items.
func validateKeywords(list []string, listName string) (string, error) {
	hasAll := false
	hasReadonly := false
	for _, item := range list {
		normalized := strings.TrimSpace(strings.ToLower(item))
		switch normalized {
		case "all":
			hasAll = true
		case "readonly":
			hasReadonly = true
		}
	}

	if (hasAll || hasReadonly) && len(list) > 1 {
		return "", fmt.Errorf("special keyword ('all' or 'readonly') in %s cannot be used together with other items", listName)
	}

	if hasAll {
		return "all", nil
	}
	if hasReadonly {
		return "readonly", nil
	}

	return "", nil
}

// A category is either an explicit allowlist or an unrestricted baseline with
// named exclusions. The latter also admits IDs introduced by future kernels.
type policyCategory[T comparable] struct {
	all     bool
	allowed map[T]struct{}
	denied  map[T]struct{}
}

func (c policyCategory[T]) allows(id T) bool {
	if _, denied := c.denied[id]; denied {
		return false
	}
	_, allowed := c.allowed[id]
	return c.all || allowed
}

func (c policyCategory[T]) unrestricted() bool { return c.all && len(c.denied) == 0 }

type policy struct {
	helpers         policyCategory[asm.BuiltinFunc]
	programTypes    policyCategory[ebpf.ProgramType]
	readonlyHelpers bool
}

func newPolicyCategory[T comparable](add, drop []string, path string, parse func(string) (T, error), readonly map[T]struct{}) (policyCategory[T], error) {
	var c policyCategory[T]
	addKeyword, err := validateKeywords(add, path+".add")
	if err != nil {
		return c, err
	}
	dropKeyword, err := validateKeywords(drop, path+".drop")
	if err != nil {
		return c, err
	}
	if dropKeyword == "readonly" {
		return c, fmt.Errorf("%s.drop: readonly is only valid in add", path)
	}
	if addKeyword == "all" && dropKeyword == "all" {
		return c, fmt.Errorf("%s: add all and drop all are contradictory", path)
	}
	c.all = (len(add) == 0 || addKeyword == "all") && dropKeyword != "all"
	c.allowed = make(map[T]struct{})
	c.denied = make(map[T]struct{})
	if addKeyword == "readonly" {
		maps.Copy(c.allowed, readonly)
	}
	if addKeyword == "" {
		for _, name := range add {
			id, err := parse(name)
			if err != nil {
				return c, fmt.Errorf("%s.add: %w", path, err)
			}
			c.allowed[id] = struct{}{}
		}
	}
	if dropKeyword == "" {
		for _, name := range drop {
			id, err := parse(name)
			if err != nil {
				return c, fmt.Errorf("%s.drop: %w", path, err)
			}
			c.denied[id] = struct{}{}
		}
	}
	return c, nil
}

// NewPolicy takes an immutable snapshot of both independently configured categories.
func NewPolicy(c *Config) (*policy, error) {
	if c == nil {
		c = &Config{}
	}
	p := &policy{}
	var err error
	p.helpers, err = newPolicyCategory(c.Policy.Helpers.Add, c.Policy.Helpers.Drop, ConfigKey+".policy.helpers", helperNameToFunc, readonlyHelpers)
	if err != nil {
		return nil, err
	}
	p.programTypes, err = newPolicyCategory(c.Policy.ProgramTypes.Add, c.Policy.ProgramTypes.Drop, ConfigKey+".policy.programTypes", programTypeNameToType, readonlyProgramTypes)
	if err != nil {
		return nil, err
	}
	p.readonlyHelpers = len(c.Policy.Helpers.Add) == 1 && strings.EqualFold(strings.TrimSpace(c.Policy.Helpers.Add[0]), "readonly")
	return p, nil
}

// extractHelpers extracts all BPF helper function calls from a program.
func extractHelpers(prog *ebpf.ProgramSpec) map[asm.BuiltinFunc]struct{} {
	helpers := make(map[asm.BuiltinFunc]struct{})

	for _, inst := range prog.Instructions {
		if inst.IsBuiltinCall() {
			helper := asm.BuiltinFunc(inst.Constant)
			helpers[helper] = struct{}{}
		}
	}

	return helpers
}
