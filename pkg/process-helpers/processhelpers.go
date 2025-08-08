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

package processhelpers

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// Clock ticks per second (constant on Linux for all architectures except alpha and ia64)
	// This could be determined dynamically using sysconf(_SC_CLK_TCK) in C
	// See e.g.
	// https://git.musl-libc.org/cgit/musl/tree/src/conf/sysconf.c#n30
	// https://github.com/containerd/cgroups/pull/12
	// https://lore.kernel.org/lkml/agtlq6$iht$1@penguin.transmeta.com/
	clockTicksPerSecond = 100
)

// ProcessInfo represents information about a running process
type ProcessInfo struct {
	PID              int       `json:"pid"`
	PPID             int       `json:"ppid"`
	Comm             string    `json:"comm"`
	CPUUsage         float64   `json:"cpuUsage"`         // CPU usage in percentage
	CPUUsageRelative float64   `json:"cpuUsageRelative"` // CPU usage in percentage, relative to number of cores
	CPUTime          uint64    `json:"cpuTime"`          // Total CPU time
	Priority         int64     `json:"priority"`         // Process priority
	Nice             int64     `json:"nice"`             // Nice Value
	MemoryRSS        uint64    `json:"memoryRSS"`        // Resident Set Size in bytes
	MemoryVirtual    uint64    `json:"memoryVirtual"`    // Virtual memory size in bytes
	MemoryShared     uint64    `json:"memoryShared"`     // Shared memory size in bytes
	MemoryRelative   float64   `json:"memoryRelative"`   // Percentage of memory usage of the system
	ThreadCount      int       `json:"threadCount"`      // Number of threads
	State            string    `json:"state"`            // Process state (R: running, S: sleeping, etc.)
	Uid              uint32    `json:"uid"`              // UID of the process owner
	StartTime        uint64    `json:"startTime"`        // Process start time (clock ticks since system boot)
	StartTimeStr     time.Time `json:"startTimeStr"`     // Process start time as a formatted string
	MountNsID        uint64    `json:"mountnsid"`        // Mount namespace ID
}

type Options interface {
	WithCPUUsage() bool
	WithCPUUsageRelative() bool
	WithComm() bool
	WithPPID() bool
	WithState() bool
	WithUID() bool
	WithVmSize() bool
	WithVmRSS() bool
	WithMemoryRelative() bool
	WithThreadCount() bool
	WithStartTime() bool

	TotalMemory() uint64
	NumCPU() int

	LastCPUTime(pid int) (uint64, bool)
	BootTime() time.Time
}

func needStatus(options Options) bool {
	return options.WithPPID() ||
		options.WithComm() ||
		options.WithState() ||
		options.WithUID() ||
		options.WithVmRSS() ||
		options.WithVmSize() ||
		options.WithMemoryRelative() ||
		options.WithThreadCount()
}

func needStat(options Options) bool {
	return options.WithCPUUsage() || options.WithCPUUsageRelative() || options.WithStartTime()
}

// buffer pool to reuse read buffers and minimize allocations
var bufPool = sync.Pool{
	New: func() interface{} {
		buf := make([]byte, 64*1024)
		return &buf
	},
}

var builderPool = sync.Pool{New: func() interface{} { b := new(bytes.Buffer); return b }}

// parseSigned parses a []byte of signed decimal digits without allocations
func parseSigned(b []byte) int64 {
	var v int64
	mult := int64(1)
	for _, c := range b {
		if c == '-' {
			mult = -1
			continue
		}
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + int64(c-'0')
	}
	return v * mult
}

// parseDecimal parses a []byte of decimal digits without allocations
func parseDecimal(b []byte) uint64 {
	var v uint64
	for _, c := range b {
		if c < '0' || c > '9' {
			break
		}
		v = v*10 + uint64(c-'0')
	}
	return v
}

// parseTrimDecimal parses a []byte of decimal digits without allocations and removes leading spaces
func parseTrimDecimal(b []byte) uint64 {
	var v uint64
	started := false
	for _, c := range b {
		if c < '0' || c > '9' {
			if c == ' ' && !started {
				continue
			}
			break
		}
		started = true
		v = v*10 + uint64(c-'0')
	}
	return v
}

var (
	prefName     = []byte("Name:\t")
	prefPPid     = []byte("PPid:\t")
	prefState    = []byte("State:\t")
	prefUid      = []byte("Uid:\t")
	prefVmSize   = []byte("VmSize:\t")
	prefVmRSS    = []byte("VmRSS:\t")
	prefVmShared = []byte("RssShmem:\t")
	prefVmFile   = []byte("RssFile:\t")
	prefThreads  = []byte("Threads:\t")
)

func GetTotalMemory() (uint64, error) {
	path := filepath.Join(host.HostProcFs, "meminfo")
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening meminfo: %w", err)
	}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		suffix, ok := bytes.CutPrefix(scanner.Bytes(), []byte("MemTotal:"))
		if !ok {
			continue
		}
		memBytes, ok := bytes.CutSuffix(bytes.TrimSpace(suffix), []byte(" kB"))
		if !ok {
			return 0, fmt.Errorf("unexpected contents of total memory field: %q", suffix)
		}
		b, err := strconv.ParseUint(string(memBytes), 10, 64)
		if err != nil {
			return 0, fmt.Errorf("parsing total memory field: %w", err)
		}
		return b * 1024, nil
	}
	return 0, fmt.Errorf("getting total memory from meminfo")
}

// readBytes fully reads s into a byte slice provided by bufPool; in case of error, it also
// returns it. In case of success, it's up to the caller to return it.
func readBytes(s io.Reader) (*[]byte, int, error) {
	xbuf := bufPool.Get().(*[]byte)
	n := 0
	for {
		r, e := s.Read((*xbuf)[n:])
		if r > 0 {
			n += r
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			bufPool.Put(xbuf)
			return nil, 0, fmt.Errorf("reading file: %w", e)
		}
	}
	return xbuf, n, nil
}

func GetProcessInfo(pid int, timeDelta float64, options Options) (ProcessInfo, error) {
	pi := ProcessInfo{PID: pid}

	// read status file to extract requested data
	if needStatus(options) {
		path := filepath.Join(host.HostProcFs, strconv.Itoa(pid), "status")
		s, err := os.Open(path)
		if err != nil {
			return pi, fmt.Errorf("opening status file for pid %d: %w", pid, err)
		}
		xbuf, n, err := readBytes(s)
		if err != nil {
			return pi, fmt.Errorf("reading status file for pid %d: %w", pid, err)
		}
		s.Close()
		data := (*xbuf)[:n]

		bComm := options.WithComm()
		bPPID := options.WithPPID()
		bState := options.WithState()
		bUid := options.WithUID()
		bVmSize := options.WithVmSize()
		bVmRSS := options.WithVmRSS()
		bThreads := options.WithThreadCount()
		bVmShared := options.WithVmSize() // same as above
		bVmFile := options.WithVmSize()

		if options.WithMemoryRelative() {
			bVmRSS = true
		}

		for i := 0; i < len(data); {
			j := bytes.IndexByte(data[i:], '\n')
			if j < 0 {
				j = len(data) - i
			}
			line := data[i : i+j]

			switch {
			case bComm && bytes.HasPrefix(line, prefName):
				bComm = false
				pi.Comm = unescapeCommandBytes(line[len(prefName):])
			case bPPID && bytes.HasPrefix(line, prefPPid):
				bPPID = false
				pi.PPID = int(parseTrimDecimal(line[len(prefPPid):]))
			case bState && bytes.HasPrefix(line, prefState):
				bState = false
				if len(line) > len(prefState) {
					pi.State = string(line[len(prefState)])
				}
			case bUid && bytes.HasPrefix(line, prefUid):
				bUid = false
				pi.Uid = uint32(parseTrimDecimal(line[len(prefUid):]))
			case bVmSize && bytes.HasPrefix(line, prefVmSize):
				bVmSize = false
				pi.MemoryVirtual = parseTrimDecimal(line[len(prefVmSize):]) * 1024
			case bVmRSS && bytes.HasPrefix(line, prefVmRSS):
				bVmRSS = false
				pi.MemoryRSS = parseTrimDecimal(line[len(prefVmRSS):]) * 1024
			case bVmShared && bytes.HasPrefix(line, prefVmShared):
				bVmShared = false
				pi.MemoryShared += parseTrimDecimal(line[len(prefVmShared):]) * 1024
			case bVmFile && bytes.HasPrefix(line, prefVmFile):
				bVmFile = false
				pi.MemoryShared += parseTrimDecimal(line[len(prefVmFile):]) * 1024
			case bThreads && bytes.HasPrefix(line, prefThreads):
				bThreads = false
				pi.ThreadCount = int(parseTrimDecimal(line[len(prefThreads):]))
			}

			if !bComm && !bPPID && !bState && !bUid && !bVmSize && !bVmRSS && !bThreads {
				// exit early if we got everything we need
				break
			}

			i += j + 1
		}
		bufPool.Put(xbuf)
	}

	if options.WithMemoryRelative() {
		totalMem := options.TotalMemory()
		if totalMem > 0 {
			pi.MemoryRelative = 100 * float64(pi.MemoryRSS) / float64(totalMem)
		}
	}

	// read stat file to extract CPU Usage & start time
	if needStat(options) {
		path := filepath.Join(host.HostProcFs, strconv.Itoa(pid), "stat")
		s, err := os.Open(path)
		if err != nil {
			return pi, fmt.Errorf("open stat %d: %w", pid, err)
		}
		xbuf, n, err := readBytes(s)
		if err != nil {
			return pi, fmt.Errorf("reading stat file for pid %d: %w", pid, err)
		}
		s.Close()
		data := (*xbuf)[:n]

		o := bytes.IndexByte(data, '(')
		c := bytes.LastIndexByte(data, ')')
		if o < 0 || c <= o {
			bufPool.Put(xbuf)
			return pi, fmt.Errorf("invalid stat %d", pid)
		}
		r := data[c+1:]

		idx := 3 // offset field index to match https://man7.org/linux/man-pages/man5/proc_pid_stat.5.html

		var utime, stime, ticks uint64

		for i := 0; i < len(r) && idx <= 22; {
			// skip spaces
			for i < len(r) && r[i] == ' ' {
				i++
			}
			if i >= len(r) {
				break
			}
			j := i
			for j < len(r) && r[j] != ' ' {
				j++
			}
			f := r[i:j]
			switch idx {
			case 14: // utime
				utime = parseDecimal(f)
			case 15: // stime
				stime = parseDecimal(f)
			case 18:
				pi.Priority = parseSigned(f)
			case 19:
				pi.Nice = parseSigned(f)
			case 22:
				ticks = parseDecimal(f)
			}
			idx++
			i = j
		}
		bufPool.Put(xbuf)

		if options.WithCPUUsage() || options.WithCPUUsageRelative() {
			pi.CPUTime = utime + stime
			if prev, ok := options.LastCPUTime(pi.PID); ok && timeDelta > 0 {
				d := float64(pi.CPUTime - prev)
				if d < 0 {
					d = float64(pi.CPUTime)
				}
				pi.CPUUsage = 100 * d / clockTicksPerSecond / timeDelta // d / clockTicksPerSecond / timeDelta * 100
				if options.WithCPUUsageRelative() {
					pi.CPUUsageRelative = pi.CPUUsage / float64(options.NumCPU())
				}
			}
		}

		if options.WithStartTime() {
			pi.StartTime = ticks
			sec := float64(ticks) / clockTicksPerSecond
			pi.StartTimeStr = options.BootTime().Add(time.Duration(sec * float64(time.Second)))
		}
	}

	return pi, nil
}

// unescapeCommandBytes unescapes the command string according to kernel escaping rules
// %ESCAPE_SPACE: ('\f', '\n', '\r', '\t', '\v')
// %ESCAPE_SPECIAL: ('\"', '\\', '\a', '\e')
func unescapeCommandBytes(cmd []byte) string {
	if bytes.IndexByte(cmd, '\\') < 0 {
		return string(cmd)
	}
	b := builderPool.Get().(*bytes.Buffer)
	b.Reset()
	b.Grow(len(cmd))
	for i := 0; i < len(cmd); i++ {
		if cmd[i] == '\\' && i+1 < len(cmd) {
			switch cmd[i+1] {
			case 'f':
				b.WriteByte('\f') // form feed
			case 'n':
				b.WriteByte('\n') // new line
			case 'r':
				b.WriteByte('\r') // carriage return
			case 't':
				b.WriteByte('\t') // horizontal tab
			case 'v':
				b.WriteByte('\v') // vertical tab
			case '"':
				b.WriteByte('"') // double quote
			case '\\':
				b.WriteByte('\\') // backslash
			case 'a':
				b.WriteByte('\a') // alert
			case 'e':
				b.WriteByte(27) // escape
			default:
				b.Write(cmd[i : i+2])
			}
			i++
		} else {
			b.WriteByte(cmd[i])
		}
	}
	s := b.String()
	builderPool.Put(b)
	return s
}
