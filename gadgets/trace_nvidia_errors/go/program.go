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

// Package main is the WASM enricher for the trace_nvidia_errors gadget.
//
// It subscribes to the single "nvidia_errors" datasource emitted by the BPF
// program and fans out on `source_raw`:
//
//	SOURCE_CUDA_API → look up CUDA CUresult + API name, run arg heuristics
//	SOURCE_XID      → look up XID, format PCI address
//
// The catalog is embedded at compile time (WASM has no filesystem access).
package main

import (
	"fmt"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const (
	sourceCUDAAPI = 1
	sourceXID     = 2
)

// CUDA error codes (CUresult enum from cuda.h, stable across CUDA versions)
// Reference: https://docs.nvidia.com/cuda/cuda-driver-api/group__CUDA__TYPES.html (enum CUresult)
const (
	cudaErrInvalidValue   int32 = 1
	cudaErrOutOfMemory    int32 = 2
	cudaErrNoDevice       int32 = 100
	cudaErrInvalidDevice  int32 = 101
	cudaErrIllegalAddress int32 = 700
	cudaErrLaunchOutOfRes int32 = 701
	cudaErrLaunchFailed   int32 = 719
)

// API IDs (mirrors program.bpf.c API_* defines)
const (
	apiCuMemAlloc_v2      uint32 = 1
	apiCuMemAllocPitch_v2 uint32 = 2
	apiCuMemAllocManaged  uint32 = 3
	apiCuLaunchKernel     uint32 = 4
	apiCuCtxCreate_v2     uint32 = 5
	apiCuDeviceGet        uint32 = 6
	apiCuModuleLoad       uint32 = 8
	apiCuModuleLoadData   uint32 = 9
	apiCuInit             uint32 = 22
)

// ─── CUDA error catalog ────────────────────────────────────────────────────
//
// Data sourced from NVIDIA Driver API documentation
// (https://docs.nvidia.com/cuda/cuda-driver-api/group__CUDA__TYPES.html)
// and cross-referenced against driver 550+ headers. Only codes with a clear,
// actionable description are included; unrecognised codes are rendered as
// CUDA_ERROR_<n> with a generic suggestion.

type cudaEntry struct {
	name        string
	category    string
	severity    string // LOW | MEDIUM | HIGH | CRITICAL
	description string
	suggestion  string
}

var cudaCatalog = map[int32]cudaEntry{
	1:   {"CUDA_ERROR_INVALID_VALUE", "parameter", "MEDIUM", "Invalid parameter passed to a CUDA Driver API call (NULL pointer, out-of-range, invalid handle).", "Log call arguments; validate sizes/pointers; check alignment requirements for device pointers."},
	2:   {"CUDA_ERROR_OUT_OF_MEMORY", "memory", "HIGH", "GPU memory allocation request exceeded free device memory.", "Reduce batch size; enable gradient checkpointing; torch.cuda.empty_cache(); check for leaks with memory_summary()."},
	3:   {"CUDA_ERROR_NOT_INITIALIZED", "lifecycle", "MEDIUM", "CUDA driver not initialized — cuInit() was not called or failed.", "Call cuInit(0) before any API; verify nvidia-smi works; check LD_LIBRARY_PATH."},
	4:   {"CUDA_ERROR_DEINITIALIZED", "lifecycle", "MEDIUM", "CUDA driver is shutting down; subsequent calls are invalid.", "Ensure CUDA operations complete before atexit; join all CUDA threads first."},
	5:   {"CUDA_ERROR_PROFILER_DISABLED", "profiler", "LOW", "Profiler API disabled in this build.", "Use nsys/ncu instead; remove deprecated cuProfiler* calls."},
	34:  {"CUDA_ERROR_STUB_LIBRARY", "driver", "HIGH", "Application linked/loaded the stub libcuda.so shipped with the toolkit rather than the real driver.", "Ensure libcuda.so from NVIDIA driver precedes toolkit stub in LD_LIBRARY_PATH."},
	100: {"CUDA_ERROR_NO_DEVICE", "device", "HIGH", "No CUDA-capable GPU detected.", "Check nvidia-smi; verify NVIDIA_VISIBLE_DEVICES; verify container runtime nvidia hook."},
	101: {"CUDA_ERROR_INVALID_DEVICE", "device", "MEDIUM", "Device ordinal out of range [0, N-1].", "Query cuDeviceGetCount first; clamp ordinal."},
	102: {"CUDA_ERROR_DEVICE_NOT_LICENSED", "device", "HIGH", "vGPU requires a license that is not checked-out.", "Verify license server reachability; nvidia-smi -q -d LICENSE."},
	200: {"CUDA_ERROR_INVALID_IMAGE", "compilation", "MEDIUM", "Device kernel image (PTX/cubin) malformed or incompatible.", "Rebuild with matching -arch=sm_XX; verify CUDA toolkit version."},
	201: {"CUDA_ERROR_INVALID_CONTEXT", "context", "MEDIUM", "No current context on the calling thread or context has been destroyed.", "cuCtxPushCurrent; avoid sharing handles across threads without synchronization."},
	202: {"CUDA_ERROR_CONTEXT_ALREADY_CURRENT", "context", "LOW", "Redundant cuCtxSetCurrent — context already active.", "Remove the redundant push; likely a library double-init."},
	205: {"CUDA_ERROR_MAP_FAILED", "interop", "MEDIUM", "Graphics resource map to CUDA failed.", "Re-register resource; verify driver versions match for OpenGL/CUDA."},
	206: {"CUDA_ERROR_UNMAP_FAILED", "interop", "MEDIUM", "Unmap call without matching map.", "Audit map/unmap pairing."},
	207: {"CUDA_ERROR_ARRAY_IS_MAPPED", "interop", "LOW", "Array cannot be modified while mapped.", "Unmap before modifying."},
	208: {"CUDA_ERROR_ALREADY_MAPPED", "interop", "LOW", "cuGraphicsMapResources called twice.", "Remove duplicate map call."},
	209: {"CUDA_ERROR_NO_BINARY_FOR_GPU", "compilation", "HIGH", "No kernel binary found for this GPU compute capability.", "Add PTX in fatbin (-arch=compute_80 -code=sm_80,compute_80) for forward compatibility."},
	210: {"CUDA_ERROR_ALREADY_ACQUIRED", "interop", "LOW", "Resource acquired twice.", "Remove duplicate acquisition."},
	211: {"CUDA_ERROR_NOT_MAPPED", "interop", "MEDIUM", "Access on unmapped resource.", "Call cuGraphicsMapResources first."},
	214: {"CUDA_ERROR_ECC_UNCORRECTABLE", "hardware", "CRITICAL", "Uncorrectable ECC memory error on GPU DRAM.", "Stop workload; nvidia-smi -q -d ECC; consider RMA if recurring."},
	215: {"CUDA_ERROR_UNSUPPORTED_LIMIT", "device", "LOW", "Limit type not supported on this GPU.", "Check compute capability matrix."},
	216: {"CUDA_ERROR_CONTEXT_ALREADY_IN_USE", "context", "MEDIUM", "Context bound to another thread.", "Use cuCtxPopCurrent/PushCurrent pattern."},
	217: {"CUDA_ERROR_PEER_ACCESS_UNSUPPORTED", "p2p", "MEDIUM", "Peer access not supported between these GPUs.", "nvidia-smi topo -m; use NVLink-connected GPUs."},
	218: {"CUDA_ERROR_INVALID_PTX", "compilation", "MEDIUM", "PTX JIT compilation failed; malformed or incompatible PTX.", "Regenerate PTX with matching toolkit; update driver."},
	219: {"CUDA_ERROR_INVALID_GRAPHICS_CONTEXT", "interop", "MEDIUM", "Graphics context invalid for CUDA interop.", "Verify GL/Vulkan context before interop init."},
	220: {"CUDA_ERROR_NVLINK_UNCORRECTABLE", "hardware", "CRITICAL", "Uncorrectable NVLink fabric error.", "nvidia-smi nvlink -e; check NVSwitch logs; likely RMA."},
	700: {"CUDA_ERROR_ILLEGAL_ADDRESS", "memory", "CRITICAL", "GPU kernel dereferenced an illegal device address (OOB, use-after-free, stale pointer).", "Run with CUDA_LAUNCH_BLOCKING=1 and compute-sanitizer --tool memcheck."},
	701: {"CUDA_ERROR_LAUNCH_OUT_OF_RESOURCES", "launch", "HIGH", "Launch needs more threads/registers/shared-mem than GPU offers.", "Lower block dim; --maxrregcount; reduce shared-mem usage."},
	702: {"CUDA_ERROR_LAUNCH_TIMEOUT", "launch", "HIGH", "Kernel exceeded display driver watchdog.", "Split into smaller kernels; disable watchdog on headless GPUs."},
	703: {"CUDA_ERROR_LAUNCH_INCOMPATIBLE_TEXTURING", "launch", "MEDIUM", "Kernel uses incompatible texturing mode.", "Audit texture bindings; unbind between kernels."},
	719: {"CUDA_ERROR_LAUNCH_FAILED", "launch", "HIGH", "Unspecified kernel failure — usually masks an illegal memory access.", "CUDA_LAUNCH_BLOCKING=1 + compute-sanitizer memcheck; inspect prior 700."},
	720: {"CUDA_ERROR_COOPERATIVE_LAUNCH_TOO_LARGE", "launch", "MEDIUM", "Cooperative launch grid exceeds device max resident blocks.", "Query cudaOccupancyMaxActiveBlocksPerMultiprocessor; clamp grid."},
	800: {"CUDA_ERROR_NOT_PERMITTED", "permission", "MEDIUM", "Operation not permitted in current context (MIG, compute mode, peer access).", "Check nvidia-smi -q -d COMPUTE; enable peer access; review MIG config."},
	911: {"CUDA_ERROR_EXTERNAL_DEVICE", "interop", "MEDIUM", "Operation on invalid external-memory handle (Vulkan/D3D import).", "Re-import the external resource; verify fd lifetime."},
	999: {"CUDA_ERROR_UNKNOWN", "unknown", "HIGH", "Driver returned unspecified failure; usually precedes XID cascade.", "dmesg | grep NVRM; restart workload; update driver."},
}

// ─── CUDA API name catalog ────────────────────────────────────────────────

var apiNames = map[uint32]string{
	1:  "cuMemAlloc_v2",
	2:  "cuMemAllocPitch_v2",
	3:  "cuMemAllocManaged",
	4:  "cuLaunchKernel",
	5:  "cuCtxCreate_v2",
	6:  "cuDeviceGet",
	7:  "cuDeviceGetCount",
	8:  "cuModuleLoad",
	9:  "cuModuleLoadData",
	10: "cuModuleGetFunction",
	11: "cuMemcpyHtoD_v2",
	12: "cuMemcpyDtoH_v2",
	13: "cuStreamCreate",
	14: "cuStreamQuery",
	15: "cuStreamSynchronize",
	16: "cuEventCreate",
	17: "cuEventRecord",
	18: "cuEventQuery",
	19: "cuEventSynchronize",
	20: "cuMemFree_v2",
	21: "cuCtxSynchronize",
	22: "cuInit",
}

// ─── XID catalog ──────────────────────────────────────────────────────────
//
// Sourced from https://docs.nvidia.com/deploy/xid-errors/ . Covers the codes
// most frequently seen in production CUDA workloads; uncatalogued codes are
// rendered as XID_<n>.

type xidEntry struct {
	name        string
	category    string
	severity    string
	description string
	suggestion  string
}

var xidCatalog = map[uint32]xidEntry{
	13:  {"Graphics Engine Exception", "app_error", "HIGH", "Illegal instruction / OOB operation executed by a GPU shader.", "compute-sanitizer memcheck + CUDA_LAUNCH_BLOCKING=1; recompile for correct arch."},
	31:  {"GPU memory page fault", "app_error", "CRITICAL", "GPU MMU fault on invalid virtual address.", "compute-sanitizer memcheck; check UVM eviction; audit cuMemcpy arguments."},
	32:  {"Invalid/corrupted push buffer", "driver_bug", "CRITICAL", "Command buffer submitted to GPU is malformed.", "Driver bug most of the time — update driver; check PCIe errors."},
	38:  {"Driver firmware error", "firmware", "CRITICAL", "Firmware/driver communication failure.", "Update firmware; check thermals; collect nvidia-bug-report."},
	43:  {"GPU watchdog timeout", "app_error", "HIGH", "Kernel exceeded watchdog timer.", "Split long kernels; add early-exit checks; raise TDR if applicable."},
	44:  {"Graphics context error", "app_error", "HIGH", "Error in graphics (not compute) context.", "Separate compute/display GPUs."},
	45:  {"Preemptive cleanup", "cleanup", "MEDIUM", "Driver is cleaning up after a preceding fatal error.", "Find and fix the root-cause XID that occurred just before XID 45."},
	48:  {"Double Bit ECC", "hardware_ecc", "CRITICAL", "Uncorrectable ECC DRAM failure.", "Stop workload; nvidia-smi -q -d ECC; RMA GPU."},
	56:  {"Display engine error", "display", "MEDIUM", "Display pipeline error.", "Check cables/monitor."},
	57:  {"Display engine channel error", "display", "MEDIUM", "Display channel error.", "Update display driver."},
	61:  {"PMU_HALT_INTERNAL", "firmware", "CRITICAL", "GPU firmware hit internal error; micro-controller breakpoint.", "Reset GPU; collect nvidia-bug-report."},
	62:  {"PMU_HALT", "firmware", "CRITICAL", "GPU firmware halted unrecoverably.", "System reboot; possible RMA."},
	63:  {"ECC page retirement event", "hardware_ecc", "MEDIUM", "GPU retiring a DRAM page.", "Monitor retired-pages count; trend indicates failing DRAM."},
	64:  {"ECC page retirement failure", "hardware_ecc", "HIGH", "Retirement table full or write failed.", "GPU DRAM degrading; plan RMA."},
	68:  {"NVDEC0 Exception", "engine", "MEDIUM", "Video decoder engine error.", "Update driver; reduce decode rate."},
	69:  {"Graphics engine class error", "engine", "HIGH", "Engine class-level error.", "Check thermals; update driver."},
	74:  {"NVLink error", "fabric", "HIGH", "NVLink semaphore timeout / access violation.", "nvidia-smi nvlink -e; check NVSwitch."},
	79:  {"GPU has fallen off the bus", "hardware_bus", "CRITICAL", "PCIe link to GPU lost.", "Check power/cables; reboot; if persistent RMA."},
	92:  {"High single-bit ECC rate", "hardware_ecc", "HIGH", "Elevated correctable ECC rate.", "nvidia-smi -q -d ECC; plan replacement."},
	94:  {"Contained ECC error", "hardware_ecc", "MEDIUM", "Contained ECC error — data corrected.", "Monitor frequency."},
	95:  {"Uncontained ECC error", "hardware_ecc", "CRITICAL", "ECC error could not be contained.", "Reset GPU; rerun workload."},
	109: {"Context switch failure", "engine", "CRITICAL", "Engine context switch failed.", "Driver bug report; firmware update."},
	119: {"GSP RPC timeout", "firmware", "CRITICAL", "GPU System Processor RPC timed out.", "Disable GSP (options nvidia NVreg_EnableGpuFirmware=0) or update driver."},
}

// ─── Field handles (populated in gadgetInit) ──────────────────────────────

var (
	dsErrors api.DataSource

	fSourceRaw                               api.Field
	fErrorCodeRaw                            api.Field
	fAPIIDRaw                                api.Field
	fXidCode                                 api.Field
	fPCIDomain                               api.Field
	fPCIBus                                  api.Field
	fPCISlot                                 api.Field
	fPCIFunc                                 api.Field
	fArg1, fArg2, fArg3, fArg4, fArg5, fArg6 api.Field

	fErrorName  api.Field
	fAPIName    api.Field
	fSourceName api.Field
	fSeverity   api.Field
	fCategory   api.Field
	fDesc       api.Field
	fWhy        api.Field
	fSuggestion api.Field
	fContext    api.Field
	fGPUAddr    api.Field

	// XID→workload correlation (patch 0002)
	fActiveCUDAAPIRaw  api.Field
	fXIDAttribFlags    api.Field
	fActiveCUDADeltaNS api.Field
	fActiveCUDACall    api.Field
	fXIDAttribution    api.Field
)

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var err error
	dsErrors, err = api.GetDataSource("nvidia_errors")
	if err != nil {
		api.Warnf("trace_nvidia_errors: datasource: %v", err)
		return 1
	}
	if err = bindRawFields(); err != nil {
		api.Warnf("trace_nvidia_errors: bind raw: %v", err)
		return 1
	}
	if err = addDerivedFields(); err != nil {
		api.Warnf("trace_nvidia_errors: add derived: %v", err)
		return 1
	}
	dsErrors.Subscribe(enrich, 0)
	return 0
}

func bindRawFields() error {
	var err error
	for _, b := range []struct {
		f    *api.Field
		name string
	}{
		{&fSourceRaw, "source_raw"},
		{&fErrorCodeRaw, "error_code_raw"},
		{&fAPIIDRaw, "api_id_raw"},
		{&fXidCode, "xid_code"},
		{&fPCIDomain, "pci_domain"},
		{&fPCIBus, "pci_bus"},
		{&fPCISlot, "pci_slot"},
		{&fPCIFunc, "pci_func"},
		{&fArg1, "arg1"}, {&fArg2, "arg2"}, {&fArg3, "arg3"},
		{&fArg4, "arg4"}, {&fArg5, "arg5"}, {&fArg6, "arg6"},
		{&fActiveCUDAAPIRaw, "active_cuda_api"},
		{&fXIDAttribFlags, "xid_attrib_flags"},
		{&fActiveCUDADeltaNS, "active_cuda_delta_ns"},
	} {
		*b.f, err = dsErrors.GetField(b.name)
		if err != nil {
			return fmt.Errorf("get field %s: %w", b.name, err)
		}
	}
	return nil
}

func addDerivedFields() error {
	var err error
	for _, b := range []struct {
		f    *api.Field
		name string
	}{
		{&fErrorName, "error_code"},
		{&fAPIName, "api_id"},
		{&fSourceName, "source"},
		{&fSeverity, "severity"},
		{&fCategory, "category"},
		{&fDesc, "description"},
		{&fWhy, "why"},
		{&fSuggestion, "suggestion"},
		{&fContext, "context_info"},
		{&fGPUAddr, "gpu_pci_addr"},
		{&fActiveCUDACall, "active_cuda_call"},
		{&fXIDAttribution, "xid_attribution"},
	} {
		*b.f, err = dsErrors.AddField(b.name, api.Kind_String)
		if err != nil {
			return fmt.Errorf("add field %s: %w", b.name, err)
		}
	}
	return nil
}

// enrich is the per-event subscription callback.
func enrich(source api.DataSource, data api.Data) {
	src, _ := fSourceRaw.Uint32(data)
	switch src {
	case sourceCUDAAPI:
		enrichCUDA(data)
	case sourceXID:
		enrichXID(data)
	default:
		fSourceName.SetString(data, "SOURCE_UNKNOWN")
	}
}

func enrichCUDA(data api.Data) {
	fSourceName.SetString(data, "SOURCE_CUDA_API")

	errCode, _ := fErrorCodeRaw.Int32(data)
	apiID, _ := fAPIIDRaw.Uint32(data)

	// error_name
	entry, known := cudaCatalog[errCode]
	if known {
		fErrorName.SetString(data, entry.name)
		fDesc.SetString(data, entry.description)
		fSuggestion.SetString(data, entry.suggestion)
		fCategory.SetString(data, entry.category)
		fSeverity.SetString(data, entry.severity)
	} else {
		fErrorName.SetString(data, fmt.Sprintf("CUDA_ERROR_%d", errCode))
		fDesc.SetString(data, "Uncatalogued CUDA error")
		fSuggestion.SetString(data, "Consult the CUDA Driver API documentation for this return code.")
		fCategory.SetString(data, "unknown")
		fSeverity.SetString(data, "MEDIUM")
	}

	// api_name
	if name, ok := apiNames[apiID]; ok {
		fAPIName.SetString(data, name)
	} else {
		fAPIName.SetString(data, fmt.Sprintf("cuda_api_%d", apiID))
	}

	// argument heuristics (context_info + why)
	a1, _ := fArg1.Uint64(data)
	a2, _ := fArg2.Uint64(data)
	a3, _ := fArg3.Uint64(data)
	a4, _ := fArg4.Uint64(data)
	a5, _ := fArg5.Uint64(data)
	a6, _ := fArg6.Uint64(data)
	ctx, why := heuristics(errCode, apiID, [6]uint64{a1, a2, a3, a4, a5, a6}, entry.description)
	fContext.SetString(data, ctx)
	fWhy.SetString(data, why)
}

func enrichXID(data api.Data) {
	fSourceName.SetString(data, "SOURCE_XID")

	xid, _ := fXidCode.Uint32(data)
	entry, known := xidCatalog[xid]
	if !known {
		entry = xidEntry{
			name:        fmt.Sprintf("XID_%d", xid),
			category:    "unknown",
			severity:    "MEDIUM",
			description: "Unrecognised XID; consult NVIDIA XID documentation.",
			suggestion:  "Update driver / check dmesg for matching NVRM line.",
		}
	}

	dom, _ := fPCIDomain.Uint32(data)
	bus, _ := fPCIBus.Uint32(data)
	slot, _ := fPCISlot.Uint32(data)
	fn, _ := fPCIFunc.Uint32(data)
	addr := fmt.Sprintf("%04x:%02x:%02x.%x", dom, bus, slot, fn)

	fErrorName.SetString(data, fmt.Sprintf("XID_%d", xid))
	fAPIName.SetString(data, "")
	fDesc.SetString(data, fmt.Sprintf("%s: %s", entry.name, entry.description))
	fSuggestion.SetString(data, entry.suggestion)
	fCategory.SetString(data, entry.category)
	fSeverity.SetString(data, entry.severity)
	fGPUAddr.SetString(data, addr)
	// XID→workload correlation (patch 0002): render the active CUDA API
	// call, attribution strategy, and augment why/context_info.
	attribFlags, _ := fXIDAttribFlags.Uint32(data)
	activeAPI, _ := fActiveCUDAAPIRaw.Uint32(data)
	activeDelta, _ := fActiveCUDADeltaNS.Int64(data)

	attribParts := []string{}
	if attribFlags&xidAttribPIDFromContext != 0 {
		attribParts = append(attribParts, "process_context")
	}
	if attribFlags&xidAttribCUDARingMatch != 0 {
		attribParts = append(attribParts, "cuda_ring_match")
	}
	if attribFlags&xidAttribUserStack != 0 {
		attribParts = append(attribParts, "user_stack")
	}
	if attribFlags&xidAttribGlobalRing != 0 {
		attribParts = append(attribParts, "global_ring")
	}
	if attribFlags&xidAttribInterruptCtx != 0 {
		attribParts = append(attribParts, "interrupt_ctx")
	}
	attribStr := "none"
	if len(attribParts) > 0 {
		attribStr = joinParts(attribParts, ",")
	}
	fXIDAttribution.SetString(data, attribStr)

	activeCall := ""
	if attribFlags&(xidAttribCUDARingMatch|xidAttribGlobalRing) != 0 {
		name, ok := apiNames[activeAPI]
		if !ok {
			name = fmt.Sprintf("cuda_api_%d", activeAPI)
		}
		activeCall = fmt.Sprintf("%s (Δ-%s ago)", name, fmtDuration(activeDelta))
	}
	fActiveCUDACall.SetString(data, activeCall)

	pidContext := "(no process context)"
	if attribFlags&xidAttribPIDFromContext != 0 {
		pidContext = "in process context"
	}
	fContext.SetString(data, fmt.Sprintf("xid=%d pci=%s active_cuda=%s attribution=%s",
		xid, addr, firstNonEmpty(activeCall, "-"), attribStr))
	whyBase := fmt.Sprintf("NVIDIA driver reported XID %d (%s) from kernel context on GPU %s %s.",
		xid, entry.name, addr, pidContext)
	if activeCall != "" {
		whyBase += fmt.Sprintf(" Offending workload last invoked %s.", activeCall)
	}
	fWhy.SetString(data, whyBase)
}

// XID→workload correlation bit-flags — mirrors program.bpf.c.
const (
	xidAttribPIDFromContext uint32 = 1 << 0
	xidAttribCUDARingMatch  uint32 = 1 << 1
	xidAttribUserStack      uint32 = 1 << 2
	xidAttribGlobalRing     uint32 = 1 << 3
	xidAttribInterruptCtx   uint32 = 1 << 4
)

// fmtDuration formats a ns delta as a short human-friendly string.
func fmtDuration(ns int64) string {
	if ns < 1000 {
		return fmt.Sprintf("%dns", ns)
	}
	if ns < 1000*1000 {
		return fmt.Sprintf("%.1fµs", float64(ns)/1000.0)
	}
	if ns < 1000*1000*1000 {
		return fmt.Sprintf("%.1fms", float64(ns)/1000000.0)
	}
	return fmt.Sprintf("%.2fs", float64(ns)/1e9)
}

func joinParts(parts []string, sep string) string {
	out := ""
	for i, s := range parts {
		if i > 0 {
			out += sep
		}
		out += s
	}
	return out
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ─── heuristics ───────────────────────────────────────────────────────────
//
// heuristics returns (context_info, why) for a CUDA error+api pair, using the
// six captured arguments. When no API-specific logic applies, context_info
// falls back to a hex dump of arg1/arg2 and why falls back to the catalog
// description.
func heuristics(errCode int32, apiID uint32, a [6]uint64, desc string) (string, string) {
	// OOM on any allocator API → size in human units
	if errCode == cudaErrOutOfMemory {
		switch apiID {
		case apiCuMemAlloc_v2, apiCuMemAllocManaged:
			return fmtBytesField("requested_bytes", a[1]),
				fmt.Sprintf("%s Allocation request %s failed.", desc, fmtBytes(a[1]))
		case apiCuMemAllocPitch_v2:
			total := a[2] * a[3]
			return fmt.Sprintf("width=%d height=%d element_size=%d (~%s)",
					a[2], a[3], a[4], fmtBytes(total)),
				fmt.Sprintf("%s Pitch allocation of ~%s failed.", desc, fmtBytes(total))
		}
	}

	// INVALID_DEVICE on cuCtxCreate or cuDeviceGet → bad ordinal
	if errCode == cudaErrInvalidDevice {
		switch apiID {
		case apiCuCtxCreate_v2:
			return fmt.Sprintf("flags=0x%x device_ordinal=%d", a[1], a[2]),
				fmt.Sprintf("%s ordinal=%d is not in [0, cuDeviceGetCount()).",
					desc, a[2])
		case apiCuDeviceGet:
			return fmt.Sprintf("ordinal=%d", a[1]),
				fmt.Sprintf("%s ordinal=%d is not in [0, cuDeviceGetCount()).",
					desc, a[1])
		}
	}

	// Launch failures → print the launch grid/block
	if (errCode == cudaErrLaunchOutOfRes || errCode == cudaErrLaunchFailed || errCode == cudaErrIllegalAddress) && apiID == apiCuLaunchKernel {
		return fmt.Sprintf("grid=(%d,%d,%d) block=(%d,%d,...)",
				a[1], a[2], a[3], a[4], a[5]),
			fmt.Sprintf("%s Launch grid=(%d,%d,%d) block=(%d,%d,...).",
				desc, a[1], a[2], a[3], a[4], a[5])
	}

	// NO_DEVICE on cuInit → context is the flags arg
	if errCode == cudaErrNoDevice && apiID == apiCuInit {
		return fmt.Sprintf("cuInit flags=0x%x", a[0]),
			fmt.Sprintf("%s No GPU visible to this process (check CUDA_VISIBLE_DEVICES).",
				desc)
	}

	// Module load failures → print pointers
	if apiID == apiCuModuleLoad || apiID == apiCuModuleLoadData {
		return fmt.Sprintf("module=0x%x data_or_path=0x%x", a[0], a[1]), desc
	}

	// Fallback
	if a[1] != 0 {
		return fmt.Sprintf("arg1=0x%x arg2=0x%x", a[0], a[1]), desc
	}
	return fmt.Sprintf("arg1=0x%x", a[0]), desc
}

// fmtBytes prints a byte count with the most-readable unit.
func fmtBytes(v uint64) string {
	const (
		gib = 1 << 30
		mib = 1 << 20
		kib = 1 << 10
	)
	switch {
	case v >= gib:
		return fmt.Sprintf("%.1f GiB", float64(v)/float64(gib))
	case v >= mib:
		return fmt.Sprintf("%.1f MiB", float64(v)/float64(mib))
	case v >= kib:
		return fmt.Sprintf("%.1f KiB", float64(v)/float64(kib))
	default:
		return fmt.Sprintf("%d B", v)
	}
}

func fmtBytesField(name string, v uint64) string {
	return fmt.Sprintf("%s=%d (%s)", name, v, fmtBytes(v))
}

func main() {}
