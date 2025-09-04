// Copyright 2025 The Inspektor Gadget authors
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

package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

// Constants from https://pkg.go.dev/syscall
// The WASM architecture redefine these constants in a different way,
// so we can't use the syscall package directly.
const (
	AF_UNIX  = 1
	AF_INET  = 2
	AF_INET6 = 10
)

type eventType uint32

const (
	syscallEventTypeEnter eventType = 0
	syscallEventTypeExit            = 1
	syscallEventTypeCont            = 2
)

// These consts must match the content of program.bpf.c.
const (
	useNullByteLength        uint64 = 0x0fffffffffffffff
	useRetAsParamLength      uint64 = 0x0ffffffffffffffe
	useArgIndexAsParamLength uint64 = 0x0ffffffffffffff0
	paramProbeAtExitMask     uint64 = 0xf000000000000000

	syscallArgs uint8 = 6

	// os.Getpagesize() in wasm will return 65536:
	// https://cs.opensource.google/go/go/+/master:src/runtime/os_wasm.go;l=13-14?q=physPageSize&ss=go%2Fgo&start=11
	// https://webassembly.github.io/spec/core/exec/runtime.html#memory-instances
	linuxPageSize uint32 = 4096

	// the max entries of the syscall_filters map
	maxSyscallFilters int = 16
)

// TODO Find all syscalls which take a char * as argument and add them there.
var syscallDefs = map[string][6]uint64{
	"execve":      {useNullByteLength, 0, 0, 0, 0, 0},
	"access":      {useNullByteLength, 0, 0, 0, 0, 0},
	"open":        {useNullByteLength, 0, 0, 0, 0, 0},
	"openat":      {0, useNullByteLength, 0, 0, 0, 0},
	"mkdir":       {useNullByteLength, 0, 0, 0, 0, 0},
	"chdir":       {useNullByteLength, 0, 0, 0, 0, 0},
	"pivot_root":  {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"mount":       {useNullByteLength, useNullByteLength, useNullByteLength, 0, 0, 0},
	"umount2":     {useNullByteLength, 0, 0, 0, 0, 0},
	"sethostname": {useNullByteLength, 0, 0, 0, 0, 0},
	"statfs":      {useNullByteLength, 0, 0, 0, 0, 0},
	"stat":        {useNullByteLength, 0, 0, 0, 0, 0},
	"statx":       {0, useNullByteLength, 0, 0, 0, 0},
	"lstat":       {useNullByteLength, 0, 0, 0, 0, 0},
	"fgetxattr":   {0, useNullByteLength, 0, 0, 0, 0},
	"lgetxattr":   {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"getxattr":    {useNullByteLength, useNullByteLength, 0, 0, 0, 0},
	"newfstatat":  {0, useNullByteLength, 0, 0, 0, 0},
	"read":        {0, useRetAsParamLength | paramProbeAtExitMask, 0, 0, 0, 0},
	"write":       {0, useArgIndexAsParamLength + 2, 0, 0, 0, 0},
	"getcwd":      {useNullByteLength | paramProbeAtExitMask, 0, 0, 0, 0, 0},
	"pread64":     {0, useRetAsParamLength | paramProbeAtExitMask, 0, 0, 0, 0},
	"connect":     {0, useArgIndexAsParamLength + 2, 0, 0, 0, 0},
}

// Used as cache for getSyscallDeclaration().
var sysDeclarationCache map[string]api.SyscallDeclaration

type eventFields struct {
	mntnsID    api.Field
	cpu        api.Field
	pid        api.Field
	comm       api.Field
	syscall    api.Field
	parameters api.Field
	ret        api.Field
}

var (
	dsOutput api.DataSource
	fields   eventFields
)

type containerRingReader struct {
	innerBuffer api.Map
	perfReader  api.PerfReader
}

type tracelooper struct {
	mapOfPerfBuffers api.Map

	// key:   mntnsID
	// value: *containerRingReader
	readers sync.Map
}

var t tracelooper

// Keep in sync with type in program.bpf.c.
type traceloopSyscallEventContT struct {
	EventType          eventType
	Param              [128]uint8
	MonotonicTimestamp uint64
	Length             uint64
	Index              uint8
	Failed             uint8
	_                  [5]byte
}

// Keep in sync with type in program.bpf.c.
type traceloopSyscallEventT struct {
	EventType          eventType
	Args               [6]uint64
	MonotonicTimestamp uint64
	BootTimestamp      uint64
	Pid                uint32
	Cpu                uint16
	Id                 uint16
	Comm               [16]uint8
	ContNr             uint8
	_                  [62]byte
}

type syscallEvent struct {
	bootTimestamp      uint64
	monotonicTimestamp uint64
	typ                eventType
	contNr             uint8
	cpu                uint16
	id                 uint16
	pid                uint32
	comm               string
	args               []uint64
	mountNsID          uint64
	retval             uint64
}

type syscallEventContinued struct {
	monotonicTimestamp uint64
	index              uint8
	param              []byte
	paramQuote         string
}

type syscallParam struct {
	name    string
	value   string
	content *string
}

type event struct {
	timestamp  int64
	mountNsID  uint64
	cpu        uint16
	pid        uint32
	comm       string
	syscall    string
	parameters []syscallParam
	retval     string
}

func paramsToString(parameters []syscallParam) string {
	var sb strings.Builder

	for idx, p := range parameters {
		value := p.value
		if p.content != nil {
			value = *p.content
		}

		fmt.Fprintf(&sb, "%s=%s", p.name, value)

		if idx < len(parameters)-1 {
			sb.WriteString(", ")
		}
	}

	return sb.String()
}

func (t *tracelooper) attach(mntnsID uint64) error {
	perfBufferName := fmt.Sprintf("perf_buffer_%d", mntnsID)

	// 1. Create inner Map as perf buffer.
	// Keep the spec in sync with program.bpf.c.
	innerBuffer, err := api.NewMap(api.MapSpec{
		Name:      perfBufferName,
		Type:      api.PerfEventArray,
		KeySize:   uint32(4),
		ValueSize: uint32(4),
	})
	if err != nil {
		return fmt.Errorf("creating map %s", fmt.Sprintf("perf_buffer_%d", mntnsID))
	}

	// 2. Use this inner Map to create the perf reader.
	perfReader, err := api.NewPerfReader(innerBuffer, 64*linuxPageSize, true)
	if err != nil {
		innerBuffer.Close()

		return fmt.Errorf("creating perf ring buffer: %w", err)
	}

	// 3. Add the inner map's file descriptor to outer map.
	err = t.mapOfPerfBuffers.Update(mntnsID, innerBuffer, api.UpdateNoExist)
	if err != nil {
		innerBuffer.Close()
		perfReader.Close()

		return fmt.Errorf("adding perf buffer to map with mntnsID %d: %w", mntnsID, err)
	}

	t.readers.Store(mntnsID, &containerRingReader{
		innerBuffer: innerBuffer,
		perfReader:  perfReader,
	})

	return nil
}

func (t *tracelooper) detach(mntnsID uint64) error {
	err := t.mapOfPerfBuffers.Delete(mntnsID)
	if err != nil {
		return fmt.Errorf("removing perf buffer from map with mntnsID %d: %w", mntnsID, err)
	}

	return nil
}

func fromCString(in []byte) string {
	idx := bytes.IndexByte(in, 0)
	switch {
	case idx == -1:
		return string(in)
	case idx < len(in):
		return string(in[:idx])
	default:
		return string(in)
	}
}

func timestampFromEvent(event *syscallEvent) int64 {
	return time.Unix(0, int64(event.bootTimestamp)).Add(0).UnixNano()
}

// Copied/pasted/adapted from kernel macro round_up:
// https://elixir.bootlin.com/linux/v6.0/source/include/linux/math.h#L25
func roundUp(x, y uintptr) uintptr {
	return ((x - 1) | (y - 1)) + 1
}

// The kernel aligns size of perf event with the following snippet:
// void perf_prepare_sample(...)
//
//	{
//		//...
//		size = round_up(sum + sizeof(u32), sizeof(u64));
//		raw->size = size - sizeof(u32);
//		frag->pad = raw->size - sum;
//		// ...
//	}
//
// (https://elixir.bootlin.com/linux/v6.0/source/kernel/events/core.c#L7353)
// In the case of our structure of interest (i.e. struct_syscall_event_t and
// struct_syscall_event_cont_t), their size will be increased by 4, here is
// an example for struct_syscall_event_t which size is 88:
// size = round_up(sum + sizeof(u32), sizeof(u64))
//
//	= round_up(88 + 4, 8)
//	= round_up(92, 8)
//	= 96
//
// raw->size = size - sizeof(u32)
//
//	= 96 - 4
//	= 92
//
// So, 4 bytes will be added as padding at the end of the event and the size we
// will read getting perfEventSample will be 92 instead of 88.
func alignSize(structSize uintptr) uintptr {
	var ret uintptr
	var foo uint64
	var bar uint32

	ret = roundUp(structSize+unsafe.Sizeof(bar), unsafe.Sizeof(foo))
	ret = ret - unsafe.Sizeof(bar)

	return ret
}

// Error table from
// https://github.com/golang/sys/blob/master/unix/zerrors_linux_amd64.go
// The list is the same between amd64 and arm64.
// The table is redefined here because it is different in the wasm
// architecture, see:
// https://github.com/golang/go/blob/master/src/syscall/tables_wasip1.go
var errorList = [...]struct {
	num  syscall.Errno
	name string
	desc string
}{
	{1, "EPERM", "operation not permitted"},
	{2, "ENOENT", "no such file or directory"},
	{3, "ESRCH", "no such process"},
	{4, "EINTR", "interrupted system call"},
	{5, "EIO", "input/output error"},
	{6, "ENXIO", "no such device or address"},
	{7, "E2BIG", "argument list too long"},
	{8, "ENOEXEC", "exec format error"},
	{9, "EBADF", "bad file descriptor"},
	{10, "ECHILD", "no child processes"},
	{11, "EAGAIN", "resource temporarily unavailable"},
	{12, "ENOMEM", "cannot allocate memory"},
	{13, "EACCES", "permission denied"},
	{14, "EFAULT", "bad address"},
	{15, "ENOTBLK", "block device required"},
	{16, "EBUSY", "device or resource busy"},
	{17, "EEXIST", "file exists"},
	{18, "EXDEV", "invalid cross-device link"},
	{19, "ENODEV", "no such device"},
	{20, "ENOTDIR", "not a directory"},
	{21, "EISDIR", "is a directory"},
	{22, "EINVAL", "invalid argument"},
	{23, "ENFILE", "too many open files in system"},
	{24, "EMFILE", "too many open files"},
	{25, "ENOTTY", "inappropriate ioctl for device"},
	{26, "ETXTBSY", "text file busy"},
	{27, "EFBIG", "file too large"},
	{28, "ENOSPC", "no space left on device"},
	{29, "ESPIPE", "illegal seek"},
	{30, "EROFS", "read-only file system"},
	{31, "EMLINK", "too many links"},
	{32, "EPIPE", "broken pipe"},
	{33, "EDOM", "numerical argument out of domain"},
	{34, "ERANGE", "numerical result out of range"},
	{35, "EDEADLK", "resource deadlock avoided"},
	{36, "ENAMETOOLONG", "file name too long"},
	{37, "ENOLCK", "no locks available"},
	{38, "ENOSYS", "function not implemented"},
	{39, "ENOTEMPTY", "directory not empty"},
	{40, "ELOOP", "too many levels of symbolic links"},
	{42, "ENOMSG", "no message of desired type"},
	{43, "EIDRM", "identifier removed"},
	{44, "ECHRNG", "channel number out of range"},
	{45, "EL2NSYNC", "level 2 not synchronized"},
	{46, "EL3HLT", "level 3 halted"},
	{47, "EL3RST", "level 3 reset"},
	{48, "ELNRNG", "link number out of range"},
	{49, "EUNATCH", "protocol driver not attached"},
	{50, "ENOCSI", "no CSI structure available"},
	{51, "EL2HLT", "level 2 halted"},
	{52, "EBADE", "invalid exchange"},
	{53, "EBADR", "invalid request descriptor"},
	{54, "EXFULL", "exchange full"},
	{55, "ENOANO", "no anode"},
	{56, "EBADRQC", "invalid request code"},
	{57, "EBADSLT", "invalid slot"},
	{59, "EBFONT", "bad font file format"},
	{60, "ENOSTR", "device not a stream"},
	{61, "ENODATA", "no data available"},
	{62, "ETIME", "timer expired"},
	{63, "ENOSR", "out of streams resources"},
	{64, "ENONET", "machine is not on the network"},
	{65, "ENOPKG", "package not installed"},
	{66, "EREMOTE", "object is remote"},
	{67, "ENOLINK", "link has been severed"},
	{68, "EADV", "advertise error"},
	{69, "ESRMNT", "srmount error"},
	{70, "ECOMM", "communication error on send"},
	{71, "EPROTO", "protocol error"},
	{72, "EMULTIHOP", "multihop attempted"},
	{73, "EDOTDOT", "RFS specific error"},
	{74, "EBADMSG", "bad message"},
	{75, "EOVERFLOW", "value too large for defined data type"},
	{76, "ENOTUNIQ", "name not unique on network"},
	{77, "EBADFD", "file descriptor in bad state"},
	{78, "EREMCHG", "remote address changed"},
	{79, "ELIBACC", "can not access a needed shared library"},
	{80, "ELIBBAD", "accessing a corrupted shared library"},
	{81, "ELIBSCN", ".lib section in a.out corrupted"},
	{82, "ELIBMAX", "attempting to link in too many shared libraries"},
	{83, "ELIBEXEC", "cannot exec a shared library directly"},
	{84, "EILSEQ", "invalid or incomplete multibyte or wide character"},
	{85, "ERESTART", "interrupted system call should be restarted"},
	{86, "ESTRPIPE", "streams pipe error"},
	{87, "EUSERS", "too many users"},
	{88, "ENOTSOCK", "socket operation on non-socket"},
	{89, "EDESTADDRREQ", "destination address required"},
	{90, "EMSGSIZE", "message too long"},
	{91, "EPROTOTYPE", "protocol wrong type for socket"},
	{92, "ENOPROTOOPT", "protocol not available"},
	{93, "EPROTONOSUPPORT", "protocol not supported"},
	{94, "ESOCKTNOSUPPORT", "socket type not supported"},
	{95, "ENOTSUP", "operation not supported"},
	{96, "EPFNOSUPPORT", "protocol family not supported"},
	{97, "EAFNOSUPPORT", "address family not supported by protocol"},
	{98, "EADDRINUSE", "address already in use"},
	{99, "EADDRNOTAVAIL", "cannot assign requested address"},
	{100, "ENETDOWN", "network is down"},
	{101, "ENETUNREACH", "network is unreachable"},
	{102, "ENETRESET", "network dropped connection on reset"},
	{103, "ECONNABORTED", "software caused connection abort"},
	{104, "ECONNRESET", "connection reset by peer"},
	{105, "ENOBUFS", "no buffer space available"},
	{106, "EISCONN", "transport endpoint is already connected"},
	{107, "ENOTCONN", "transport endpoint is not connected"},
	{108, "ESHUTDOWN", "cannot send after transport endpoint shutdown"},
	{109, "ETOOMANYREFS", "too many references: cannot splice"},
	{110, "ETIMEDOUT", "connection timed out"},
	{111, "ECONNREFUSED", "connection refused"},
	{112, "EHOSTDOWN", "host is down"},
	{113, "EHOSTUNREACH", "no route to host"},
	{114, "EALREADY", "operation already in progress"},
	{115, "EINPROGRESS", "operation now in progress"},
	{116, "ESTALE", "stale file handle"},
	{117, "EUCLEAN", "structure needs cleaning"},
	{118, "ENOTNAM", "not a XENIX named type file"},
	{119, "ENAVAIL", "no XENIX semaphores available"},
	{120, "EISNAM", "is a named type file"},
	{121, "EREMOTEIO", "remote I/O error"},
	{122, "EDQUOT", "disk quota exceeded"},
	{123, "ENOMEDIUM", "no medium found"},
	{124, "EMEDIUMTYPE", "wrong medium type"},
	{125, "ECANCELED", "operation canceled"},
	{126, "ENOKEY", "required key not available"},
	{127, "EKEYEXPIRED", "key has expired"},
	{128, "EKEYREVOKED", "key has been revoked"},
	{129, "EKEYREJECTED", "key was rejected by service"},
	{130, "EOWNERDEAD", "owner died"},
	{131, "ENOTRECOVERABLE", "state not recoverable"},
	{132, "ERFKILL", "operation not possible due to RF-kill"},
	{133, "EHWPOISON", "memory page has hardware error"},
}

// errnoName returns the error name for error number e.
func errnoName(e syscall.Errno) string {
	i := sort.Search(len(errorList), func(i int) bool {
		return errorList[i].num >= e
	})
	if i < len(errorList) && errorList[i].num == e {
		return fmt.Sprintf("%s (%s)", errorList[i].name, errorList[i].desc)
	}
	return fmt.Sprintf("(unknown error %d)", e)
}

// Convert a return value to corresponding error number if meaningful.
// See man syscalls:
// Note:
// system calls indicate a failure by returning a negative error
// number to the caller on architectures without a separate error
// register/flag, as noted in syscall(2); when this happens, the
// wrapper function negates the returned error number (to make it
// positive), copies it to errno, and returns -1 to the caller of
// the wrapper.
func retToStr(ret uint64) string {
	errNo := int64(ret)
	if errNo >= -4095 && errNo <= -1 {
		return fmt.Sprintf("-1 %s", errnoName(syscall.Errno(-errNo)))
	}
	return fmt.Sprintf("%d", ret)
}

func getSyscallDeclaration(name string) (api.SyscallDeclaration, error) {
	if sysDeclarationCache == nil {
		sysDeclarationCache = make(map[string]api.SyscallDeclaration)
	}

	if declaration, ok := sysDeclarationCache[name]; ok {
		return declaration, nil
	}

	declaration, err := api.GetSyscallDeclaration(name)
	if err != nil {
		return api.SyscallDeclaration{}, fmt.Errorf("getting syscall definition: %w", err)
	}

	sysDeclarationCache[name] = declaration

	return declaration, nil
}

// sockaddrFromBytes attempts to convert a byte slice representing a sockaddr
// into a human-readable IP address and port string.
// It handles AF_INET (IPv4), AF_INET6 (IPv6) and AF_UNIX (Unix sockets).
func sockaddrFromBytes(data []byte) (string, error) {
	if len(data) < 2 {
		return "", fmt.Errorf("sockaddr byte slice too short to determine family")
	}

	// The first two bytes of any sockaddr struct typically contain the address family.
	// This is a uint16 in native endianness. We can't use binary.NativeEndian because
	// it would be the WASM endianness. IG supports both amd64 and arm64, which are
	// both Little Endian.
	family := binary.LittleEndian.Uint16(data[0:2])

	switch family {
	case AF_INET:
		// IPv4: struct sockaddr_in
		// struct sockaddr_in {
		//     sa_family_t    sin_family; // address family: AF_INET
		//     in_port_t      sin_port;   // port in network byte order
		//     struct in_addr sin_addr;   // internet address
		// };
		// struct in_addr {
		//     uint32_t s_addr; // address in network byte order
		// };

		if len(data) < 8 {
			return "", fmt.Errorf("IPv4 sockaddr byte slice too short (%d)", len(data))
		}

		// Port is in network byte order (big-endian). Convert to host byte order.
		port := int(binary.BigEndian.Uint16(data[2:4]))

		// IP address is 4 bytes, also in network byte order.
		ip := net.IPv4(data[4], data[5], data[6], data[7])

		return fmt.Sprintf("%s:%d", ip.String(), port), nil

	case AF_INET6:
		// IPv6: struct sockaddr_in6
		// struct sockaddr_in6 {
		//     sa_family_t     sin6_family;   // AF_INET6
		//     in_port_t       sin6_port;     // port number
		//     uint32_t        sin6_flowinfo; // IPv6 flow-info
		//     struct in6_addr sin6_addr;     // IPv6 address
		//     uint32_t        sin6_scope_id; // Scope ID (for link-local addresses)
		// };
		// struct in6_addr {
		//     unsigned char   s6_addr[16];   // IPv6 address in network byte order
		// };

		if len(data) < 28 {
			return "", fmt.Errorf("IPv6 sockaddr byte slice too short (%d)", len(data))
		}

		// Port is in network byte order (big-endian). Convert to host byte order.
		port := int(binary.BigEndian.Uint16(data[2:4]))

		// IP address is 16 bytes.
		ip := net.IP(data[8 : 8+16]) // [16]byte array

		// Extract the scope ID (bytes 24-27). On amd64 and arm64, this is little-endian.
		scopeID := binary.LittleEndian.Uint32(data[24:28])

		addrStr := ip.String()
		if scopeID != 0 {
			addrStr = fmt.Sprintf("%s%%%d", addrStr, scopeID)
		}

		return fmt.Sprintf("[%s]:%d", addrStr, port), nil

	case AF_UNIX:
		// Unix domain socket: struct sockaddr_un
		// struct sockaddr_un {
		//     sa_family_t sun_family; // AF_UNIX
		//     char        sun_path[108]; // Pathname
		// };
		// The path can be abstract (starts with NUL byte) or filesystem path.

		// The path can be shorter than 108 bytes but at least 1 byte
		if len(data) < 3 {
			return "", fmt.Errorf("Unix sockaddr byte slice too short (%d)", len(data))
		}
		pathBytes := data[2:]
		path := ""
		if pathBytes[0] == 0 {
			// Abstract Unix socket: the path starts with a null byte.
			// `strace` often represents this with an "@" prefix (e.g., `unix:@/tmp/my_socket`).
			quoted := strconv.Quote(string(pathBytes[1:]))
			path = "@" + quoted[1:len(quoted)-1] // Remove double quotes
		} else {
			nullTerminator := bytes.IndexByte(pathBytes, 0)
			if nullTerminator != -1 {
				// If a null terminator is found, the path is up to that point.
				path = string(pathBytes[:nullTerminator])
			} else {
				// If no null terminator, treat the rest of the slice as the path.
				// This can happen if the buffer is exactly the size of the path.
				path = string(pathBytes)
			}
		}

		// Format as "unix:path".
		return fmt.Sprintf("unix:%s", path), nil

	default:
		return "", fmt.Errorf("unsupported address family: %d", family)
	}
}

func (t *tracelooper) read(mntnsID uint64, reader *containerRingReader) ([]*event, error) {
	syscallContinuedEventsMap := make(map[uint64][]*syscallEventContinued)
	syscallEnterEventsMap := make(map[uint64][]*syscallEvent)
	syscallExitEventsMap := make(map[uint64][]*syscallEvent)
	var sysEventCont *traceloopSyscallEventContT
	events := make([]*event, 0)
	var sysEvent *traceloopSyscallEventT

	err := reader.perfReader.Pause()
	if err != nil {
		return nil, err
	}

	sysEventSize := alignSize(unsafe.Sizeof(*sysEvent))
	for {
		record := make([]byte, sysEventSize)
		if err := reader.perfReader.Read(record); err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) {
				break
			} else {
				return nil, err
			}
		}

		sysEvent = (*traceloopSyscallEventT)(unsafe.Pointer(&record[0]))

		switch sysEvent.EventType {
		case syscallEventTypeEnter, syscallEventTypeExit:

			event := &syscallEvent{
				bootTimestamp:      sysEvent.BootTimestamp,
				monotonicTimestamp: sysEvent.MonotonicTimestamp,
				typ:                sysEvent.EventType,
				contNr:             sysEvent.ContNr,
				cpu:                sysEvent.Cpu,
				id:                 sysEvent.Id,
				pid:                sysEvent.Pid,
				comm:               fromCString(sysEvent.Comm[:]),
				mountNsID:          mntnsID,
			}

			var typeMap *map[uint64][]*syscallEvent
			switch event.typ {
			case syscallEventTypeEnter:
				event.args = make([]uint64, syscallArgs)
				for i := uint8(0); i < syscallArgs; i++ {
					event.args[i] = sysEvent.Args[i]
				}

				typeMap = &syscallEnterEventsMap
			case syscallEventTypeExit:
				event.retval = sysEvent.Args[0]

				typeMap = &syscallExitEventsMap
			}

			(*typeMap)[event.monotonicTimestamp] = append((*typeMap)[event.monotonicTimestamp], event)
		case syscallEventTypeCont:
			sysEventCont = (*traceloopSyscallEventContT)(unsafe.Pointer(&record[0]))

			event := &syscallEventContinued{
				monotonicTimestamp: sysEventCont.MonotonicTimestamp,
				index:              sysEventCont.Index,
				param:              sysEventCont.Param[:],
			}

			if sysEventCont.Failed != 0 {
				event.paramQuote = "(Failed to dereference pointer)"
			} else if sysEventCont.Length == useNullByteLength {
				// 0 byte at [C.PARAM_LENGTH - 1] is enforced in BPF code
				event.paramQuote = fromCString(sysEventCont.Param[:])
				event.param = event.param[:len(event.paramQuote)]
			} else {
				if sysEventCont.Length < uint64(len(sysEventCont.Param[:])) {
					event.paramQuote = string(sysEventCont.Param[:sysEventCont.Length])
					event.param = event.param[:sysEventCont.Length]
				} else {
					event.paramQuote = string(sysEventCont.Param[:])
				}
			}

			// Remove all non unicode character from the string.
			event.paramQuote = strconv.Quote(event.paramQuote)

			syscallContinuedEventsMap[event.monotonicTimestamp] = append(syscallContinuedEventsMap[event.monotonicTimestamp], event)
		default:
			api.Debugf("unknown event type: got %d, expected %d or %d", sysEvent.EventType, syscallEventTypeEnter, syscallEventTypeCont)
		}
	}

	err = reader.perfReader.Resume()
	if err != nil {
		return nil, err
	}

	// Publish the events we gathered.
	for enterTimestamp, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			event := &event{
				timestamp: timestampFromEvent(enterEvent),
				mountNsID: enterEvent.mountNsID,
				cpu:       enterEvent.cpu,
				pid:       enterEvent.pid,
				comm:      enterEvent.comm,
				syscall:   syscallName,
			}

			syscallDeclaration, err := getSyscallDeclaration(event.syscall)
			if err != nil {
				return nil, fmt.Errorf("getting syscall definition: %w", err)
			}

			parametersNumber := len(syscallDeclaration.Params)
			event.parameters = make([]syscallParam, parametersNumber)
			api.Debugf("\tevent parametersNumber: %d", parametersNumber)

			for i := 0; i < parametersNumber; i++ {
				paramName := syscallDeclaration.Params[i].Name
				api.Debugf("\t\tevent paramName: %q", paramName)

				isPointer := syscallDeclaration.Params[i].IsPointer

				format := "%d"
				if isPointer {
					format = "0x%x"
				}
				paramValue := fmt.Sprintf(format, enterEvent.args[i])
				api.Debugf("\t\tevent paramValue: %q", paramValue)

				var paramContent *string

				for _, syscallContEvent := range syscallContinuedEventsMap[enterTimestamp] {
					if syscallContEvent.index == uint8(i) {
						paramContent = &syscallContEvent.paramQuote
						if syscallName == "connect" && paramName == "uservaddr" {
							addrStr, err := sockaddrFromBytes(syscallContEvent.param)
							if err != nil {
								errStr := err.Error() + fmt.Sprintf(" (failed to parse %v %q)", syscallContEvent.param, syscallContEvent.paramQuote)
								paramContent = &errStr
							} else {
								paramContent = &addrStr

							}
						}
						api.Debugf("\t\t\tevent paramContent: %q", paramContent)

						break
					}
				}

				event.parameters[i] = syscallParam{
					name:    paramName,
					value:   paramValue,
					content: paramContent,
				}
			}

			delete(syscallContinuedEventsMap, enterTimestamp)

			// There is no exit event for exit(), exit_group() and rt_sigreturn().
			if event.syscall == "exit" || event.syscall == "exit_group" || event.syscall == "rt_sigreturn" {
				delete(syscallEnterEventsMap, enterTimestamp)

				// As there is no exit events for these syscalls,
				// then there is no return value.
				event.retval = "X"

				api.Debugf("%v", event)
				events = append(events, event)

				continue
			}

			exitTimestampEvents, ok := syscallExitEventsMap[enterTimestamp]
			if !ok {
				api.Debugf("no exit event for timestamp %d", enterTimestamp)

				continue
			}

			for _, exitEvent := range exitTimestampEvents {
				if enterEvent.id != exitEvent.id || enterEvent.pid != exitEvent.pid {
					continue
				}

				event.retval = retToStr(exitEvent.retval)

				delete(syscallEnterEventsMap, enterTimestamp)
				delete(syscallExitEventsMap, enterTimestamp)

				api.Debugf("%v", event)
				events = append(events, event)

				break
			}
		}
	}

	api.Debugf("len(events): %d; len(syscallEnterEventsMap): %d; len(syscallExitEventsMap): %d; len(syscallContinuedEventsMap): %d\n", len(events), len(syscallEnterEventsMap), len(syscallExitEventsMap), len(syscallContinuedEventsMap))

	// It is possible there are some incomplete events for several reasons:
	// 1. Traceloop was started in the middle of a syscall, then we will only get
	//    the exit but not the enter.
	// 2. Traceloop was stopped in the middle of a syscall, then we will only get
	//    the enter but not the exit
	// 3. The buffer is full and so it only remains some exit events and not the
	//    corresponding enter.
	// Rather than dropping these incomplete events, we just add them to the
	// events to be published.
	for _, enterTimestampEvents := range syscallEnterEventsMap {
		for _, enterEvent := range enterTimestampEvents {
			syscallName, err := api.GetSyscallName(enterEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteEnterEvent := &event{
				timestamp: timestampFromEvent(enterEvent),
				mountNsID: enterEvent.mountNsID,
				cpu:       enterEvent.cpu,
				pid:       enterEvent.pid,
				comm:      enterEvent.comm,
				syscall:   syscallName,
				retval:    "unfinished",
			}

			events = append(events, incompleteEnterEvent)

			api.Debugf("enterEvent(%q): %v\n", syscallName, enterEvent)
		}
	}

	for _, exitTimestampEvents := range syscallExitEventsMap {
		for _, exitEvent := range exitTimestampEvents {
			syscallName, err := api.GetSyscallName(exitEvent.id)
			if err != nil {
				return nil, fmt.Errorf("getting syscall name: %w", err)
			}

			incompleteExitEvent := &event{
				timestamp: timestampFromEvent(exitEvent),
				cpu:       exitEvent.cpu,
				pid:       exitEvent.pid,
				comm:      exitEvent.comm,
				mountNsID: exitEvent.mountNsID,
				syscall:   syscallName,
				retval:    retToStr(exitEvent.retval),
			}

			events = append(events, incompleteExitEvent)

			api.Debugf("exitEvent(%q): %v\n", syscallName, exitEvent)
		}
	}

	// Sort all events by ascending timestamp.
	sort.Slice(events, func(i, j int) bool {
		return events[i].timestamp < events[j].timestamp
	})

	return events, nil
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	var sysEventCont *traceloopSyscallEventContT
	var sysEvent *traceloopSyscallEventT
	var err error
	sysEventSize := alignSize(unsafe.Sizeof(*sysEvent))
	sysEventContSize := alignSize(unsafe.Sizeof(*sysEventCont))

	if sysEventSize != sysEventContSize {
		api.Errorf("event sizes must be the same, there is a mismatch: %d != %d", sysEventSize, sysEventContSize)
		return 1
	}

	dsOutput, err = api.NewDataSource("traceloop", api.DataSourceTypeSingle)
	if err != nil {
		api.Errorf("creating datasource: %v", err)
		return 1
	}

	fieldsInfo := []struct {
		name  string
		kind  api.FieldKind
		field *api.Field
	}{
		{
			name:  "mntns_id",
			kind:  api.Kind_Uint64,
			field: &fields.mntnsID,
		},
		{
			name:  "cpu",
			kind:  api.Kind_Uint16,
			field: &fields.cpu,
		},
		{
			name:  "pid",
			kind:  api.Kind_Uint32,
			field: &fields.pid,
		},
		{
			name:  "comm",
			kind:  api.Kind_String,
			field: &fields.comm,
		},
		{
			name:  "syscall",
			kind:  api.Kind_String,
			field: &fields.syscall,
		},
		{
			name:  "parameters",
			kind:  api.Kind_String,
			field: &fields.parameters,
		},
		{
			name:  "ret",
			kind:  api.Kind_String,
			field: &fields.ret,
		},
	}
	for _, fieldInfo := range fieldsInfo {
		name := fieldInfo.name
		*fieldInfo.field, err = dsOutput.AddField(name, fieldInfo.kind)
		if err != nil {
			api.Errorf("adding %s field: %v", name, err)
			return 1
		}
	}

	err = fields.mntnsID.AddTag("type:gadget_mntns_id")
	if err != nil {
		api.Errorf("adding tag to mntns_id field: %v", err)
		return 1
	}

	return 0
}

//go:wasmexport gadgetStart
func gadgetStart() int32 {
	rawString, err := api.GetParamValue("syscall-filters", 256)
	if err != nil {
		api.Errorf("failed to get param: %v", err)
		return 1
	}

	syscallsFilterMapName := "syscall_filters"
	syscallsFilterMap, err := api.GetMap(syscallsFilterMapName)
	if err != nil {
		api.Errorf("no map named %s", syscallsFilterMapName)
		return 1
	}

	var syscallFilters []string

	if rawString != "" {
		syscallFilters = strings.Split(rawString, ",")
	}

	// Try to keep the max entries in syscall_filters in sync with user code and
	// ebpf code.
	if len(syscallFilters) > maxSyscallFilters {
		api.Errorf("Length of --syscall-filters exceeded. No more than 16 values can be added.")
		return 1
	}
	for _, name := range syscallFilters {
		id, err := api.GetSyscallID(name)
		if err != nil {
			api.Errorf("syscall %q does not exist", name)
			return 1
		}

		err = syscallsFilterMap.Put(uint64(id), true)
		if err != nil {
			api.Errorf("Could not add %q (%d) to syscall filter map: %v", name, id, err)
			return 1
		}
	}

	if len(syscallFilters) > 0 {
		syscallsEnableFilterMapName := "syscall_enable_filters"
		syscallsEnableFilterMap, err := api.GetMap(syscallsEnableFilterMapName)
		if err != nil {
			api.Errorf("no map named %s", syscallsEnableFilterMapName)
			return 1
		}
		err = syscallsEnableFilterMap.Put(uint32(0), true)
		if err != nil {
			api.Errorf("Could not add not enable filter syscall: %v", err)
			return 1
		}
	}

	mapName := "map_of_perf_buffers"

	t.mapOfPerfBuffers, err = api.GetMap(mapName)
	if err != nil {
		api.Errorf("no map named %s", mapName)
		return 1
	}

	syscallsMapName := "syscalls"

	syscallsMap, err := api.GetMap(syscallsMapName)
	if err != nil {
		api.Errorf("no map named %s", syscallsMapName)
		return 1
	}

	// Fill the syscall map with specific syscall signatures.
	for name, def := range syscallDefs {
		id, err := api.GetSyscallID(name)
		if err != nil {
			// It's possible that the syscall doesn't exist for this architecture, skip it
			continue
		}

		err = syscallsMap.Put(uint64(id), def)
		if err != nil {
			api.Errorf("storing %s definition in corresponding map: %v", name, err)
			return 1
		}
	}

	ds, err := api.GetDataSource(api.DataSourceContainers)
	if err != nil {
		api.Errorf("Failed to get data source: %v", err)
		return 1
	}

	eventTypeField, err := ds.GetField("event_type")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	mntnsIDField, err := ds.GetField("mntns_id")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	nameField, err := ds.GetField("name")
	if err != nil {
		api.Errorf("Failed to get field: %v", err)
		return 1
	}

	ds.Subscribe(func(ds api.DataSource, data api.Data) {
		eventType, err := eventTypeField.String(data, api.DataSourceContainersEventTypeMaxSize)
		if err != nil {
			api.Errorf("getting event_type from corresponding field: %v", err)
			return
		}

		mntnsID, err := mntnsIDField.Uint64(data)
		if err != nil {
			api.Errorf("getting mntns_id from corresponding field: %v", err)
			return
		}

		name, err := nameField.String(data, 64)
		if err != nil {
			api.Errorf("getting name from corresponding field: %v", err)
			return
		}

		switch eventType {
		case "CREATED":
			api.Debugf("attaching %v", name)
			err = t.attach(mntnsID)
			if err != nil {
				api.Errorf("attaching container %v: %v", name, err)
				return
			}
		case "DELETED":
			api.Debugf("detaching %v", name)
			err := t.detach(mntnsID)
			if err != nil {
				api.Errorf("detaching container %v: %v", name, err)
				return
			}
		default:
			// Nothing to do, we don't care about other events.
		}
	}, 0)

	return 0
}

//go:wasmexport gadgetStop
func gadgetStop() int32 {
	t.readers.Range(func(key, value any) bool {
		mntnsID := key.(uint64)
		reader := value.(*containerRingReader)

		events, err := t.read(mntnsID, reader)
		if err != nil {
			api.Errorf("reading container: %v", err)
			return true
		}

		reader.perfReader.Close()

		for _, event := range events {
			packet, err := dsOutput.NewPacketSingle()
			if err != nil {
				api.Errorf("creating datasource packet: %v", err)
				continue
			}

			fields.mntnsID.SetUint64(api.Data(packet), event.mountNsID)
			fields.cpu.SetUint16(api.Data(packet), event.cpu)
			fields.pid.SetUint32(api.Data(packet), event.pid)
			fields.comm.SetString(api.Data(packet), event.comm)
			fields.syscall.SetString(api.Data(packet), event.syscall)
			fields.parameters.SetString(api.Data(packet), paramsToString(event.parameters))
			fields.ret.SetString(api.Data(packet), event.retval)

			dsOutput.EmitAndRelease(api.Packet(packet))
		}

		return true
	})

	return 0
}

func main() {}
