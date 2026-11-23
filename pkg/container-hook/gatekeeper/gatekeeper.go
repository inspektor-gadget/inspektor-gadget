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

// Package gatekeeper is the process that reads the container hook's fanotify
// groups and answers their permission events with a deadline, so a stalled
// container hook cannot freeze container lifecycle on the host. See
// docs/devel/container-hook-gatekeeper.md for the design; this package holds
// only the process side and the wire protocol, and imports nothing heavy, so
// the dedicated binary (cmd/container-hook-gatekeeper) stays small.
package gatekeeper

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	// ProtocolVersion is sent in the ready message. The parent refuses a
	// gatekeeper speaking another version (a separately shipped binary out
	// of step with the library).
	ProtocolVersion = 1

	// Env marks a process started as the gatekeeper.
	Env = "IG_CONTAINER_HOOK_GATEKEEPER"
	// BoundRuntimeEnv and BoundPidFileEnv are the response bounds, in
	// nanoseconds, for the runtime-binary and pid-file groups.
	BoundRuntimeEnv = "IG_CONTAINER_HOOK_GATEKEEPER_BOUND_RUNTIME_NS"
	BoundPidFileEnv = "IG_CONTAINER_HOOK_GATEKEEPER_BOUND_PIDFILE_NS"
	// RecordSizeEnv is the value size of ig_fa_records; 0 when there is no
	// record queue.
	RecordSizeEnv = "IG_CONTAINER_HOOK_GATEKEEPER_RECORD_SIZE"
	// CgroupEnv is the cgroup v2 directory under which the gatekeeper creates
	// its own child and moves itself into it, if the inherited cgroup has a
	// memory limit (see joinCgroup). Empty: stay in the inherited cgroup.
	CgroupEnv = "IG_CONTAINER_HOOK_GATEKEEPER_CGROUP"
	// CgroupForceEnv set to "1" moves the gatekeeper even when the inherited
	// cgroup has no memory limit.
	CgroupForceEnv = "IG_CONTAINER_HOOK_GATEKEEPER_CGROUP_FORCE"

	// File descriptors in the gatekeeper (exec.Cmd ExtraFiles start at 3).
	// Stdout and stderr (1, 2) are a pipe of their own, drained by the
	// parent.
	FdRuntime = 3
	FdPidFile = 4
	FdSock    = 5
	FdRecords = 6 // optional

	GroupRuntime uint8 = 0
	GroupPidFile uint8 = 1
	// GroupReady marks the ready message, the first one the gatekeeper
	// sends: seq carries ProtocolVersion, flags FlagCgroupMoved or
	// FlagCgroupNotNeeded, and the payload the cgroup directory or why it was
	// not used.
	GroupReady uint8 = 0xff

	FlagHasFd           uint8 = 1 << 0
	FlagRecordOK        uint8 = 1 << 1
	FlagHasRecord       uint8 = 1 << 2
	FlagCgroupMoved     uint8 = 1 << 3
	FlagCgroupNotNeeded uint8 = 1 << 4

	// HeaderLen is the header of a gatekeeper→parent message, followed by
	// the eBPF record for runtime events (native byte order):
	//   0  u32 seq
	//   4  u8  group
	//   5  u8  flags
	//   6  u16 reserved
	//   8  u64 mask
	//   16 i32 pid
	//   20 u32 reserved
	HeaderLen = 24
	// DoneLen is a parent→gatekeeper message: u32 seq of a processed event.
	DoneLen = 4

	// Slots is how many pending permission events are tracked. A slot reused
	// before its event was answered is allowed first (fail-open). Each one
	// holds an fd, see raiseNofile.
	Slots = 4096
	// Socket send buffer, see Run.
	sndBuf = 8 << 20

	defaultBound = time.Second
)

// Limits of each gatekeeper's cgroup. The gatekeeper needs ~2 MiB and a
// handful of threads; the limits only bound a misbehaving one and are
// generous on purpose. A permission event whose fd the kernel cannot create
// for the reader (memcg charge or fd limit) is answered FAN_DENY by the
// kernel, so the reader must never run near these.
var cgroupLimits = []struct{ file, value string }{
	{"memory.max", strconv.Itoa(256 << 20)},
	{"pids.max", "512"},
	{"cpu.max", "100000 100000"},
}

var metadataSize = int(unsafe.Sizeof(unix.FanotifyEventMetadata{}))

// IsPermMask reports whether a fanotify event mask is a permission event.
func IsPermMask(mask uint64) bool {
	return mask&(unix.FAN_OPEN_PERM|unix.FAN_ACCESS_PERM|unix.FAN_OPEN_EXEC_PERM) != 0
}

// bpfMapElemAttr is the BPF_MAP_*_ELEM variant of union bpf_attr.
type bpfMapElemAttr struct {
	mapFd uint32
	_     uint32
	key   unsafe.Pointer
	value unsafe.Pointer
	flags uint64
}

const bpfMapLookupAndDeleteElem = 21

type pendingEvent struct {
	active   bool
	group    uint8
	seq      uint32
	fd       int32
	deadline int64
}

type state struct {
	bounds     [2]int64 // per group, ns
	recordSize int
	sock       int
	records    int // -1 when there is no record queue

	seq     uint32
	pending [Slots]pendingEvent
	nActive int

	// Preallocated I/O buffers: nothing is allocated per event.
	meta    [24]byte
	msg     []byte
	oob     []byte
	done    [DoneLen * 64]byte
	resp    [8]byte
	bpfAttr bpfMapElemAttr
	pollFds [3]unix.PollFd

	// Counters, reported periodically.
	forwarded, answered, expired, dropped, evicted uint64
	lastReport                                     int64
	reported                                       [4]uint64
}

var monoBase = time.Now()

func now() int64 { return int64(time.Since(monoBase)) }

// logf writes one line to stderr, a pipe the parent drains. Stderr is
// non-blocking (see Run): when the pipe is full the line is dropped, because
// a gatekeeper blocked on logging answers nothing.
func logf(format string, args ...any) {
	_, _ = unix.Write(2, []byte("container-hook gatekeeper: "+fmt.Sprintf(format, args...)+"\n"))
}

// closeInheritedFanotifyGroups closes fanotify group fds other than ours that
// leaked in from the parent (fds without O_CLOEXEC). Holding one would keep
// that group, and its permission marks, alive after the parent closed it to
// fail open, with nobody reading it. Only fanotify groups are touched: the Go
// runtime owns other fds (epoll, eventfd) here.
func closeInheritedFanotifyGroups() {
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return
	}
	for _, e := range entries {
		fd, err := strconv.Atoi(e.Name())
		if err != nil || fd <= FdRecords {
			continue
		}
		if target, err := os.Readlink("/proc/self/fd/" + e.Name()); err == nil && target == "anon_inode:[fanotify]" {
			unix.Close(fd)
		}
	}
}

// raiseNofile makes room for Slots pending event fds. If the kernel cannot
// create the fd of a permission event for us, it answers FAN_DENY.
func raiseNofile() {
	var lim unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_NOFILE, &lim); err != nil {
		return
	}
	if lim.Cur < lim.Max {
		lim.Cur = lim.Max
		_ = unix.Setrlimit(unix.RLIMIT_NOFILE, &lim)
	}
	if lim.Cur < Slots+64 {
		logf("RLIMIT_NOFILE is %d, below %d: a burst of pending events can make the kernel deny one", lim.Cur, Slots+64)
	}
}

// CgroupDir is the cgroup a gatekeeper with the given pid runs in under base.
func CgroupDir(base string, pid int) string {
	return filepath.Join(base, strconv.Itoa(pid))
}

// errCgroupNotNeeded: the inherited cgroup has no memory limit, so memcg
// throttling cannot stall the gatekeeper there.
var errCgroupNotNeeded = errors.New("inherited cgroup has no memory limit")

// MemoryLimited reports whether the cgroup at path (as in /proc/self/cgroup,
// relative to the cgroup v2 mount at root) or one of its ancestors has a
// memory.max or memory.high limit. The root cgroup has neither file.
func MemoryLimited(root, path string) bool {
	for p := filepath.Clean("/" + path); p != "/"; p = filepath.Dir(p) {
		for _, f := range []string{"memory.max", "memory.high"} {
			b, err := os.ReadFile(filepath.Join(root, p, f))
			if err == nil && strings.TrimSpace(string(b)) != "max" {
				return true
			}
		}
	}
	return false
}

// joinCgroup moves this process into base/<pid>, out of the parent's cgroup,
// when the parent's cgroup has a memory limit (or force is set).
// Answering an event charges kernel memory (the event's struct file) to the
// reader's memcg, so a gatekeeper left in the parent's memcg is throttled in
// mem_cgroup_handle_over_high exactly when the parent is, and stops answering.
// Each gatekeeper gets its own child so instances (a rolling update, several
// embedders on one node) never share limits; stale children of gatekeepers
// that are gone are removed. The parent usually runs in a private cgroup
// namespace, which forbids migrating outside it, so the move happens from a
// thread that first joins the host cgroup namespace (/proc/1 is the host init
// with hostPID). That thread is locked and discarded afterwards.
func joinCgroup(base string, force bool) (string, error) {
	root := filepath.Dir(base)
	if _, err := os.Stat(filepath.Join(root, "cgroup.controllers")); err != nil {
		return "", fmt.Errorf("not a cgroup v2 hierarchy: %w", err)
	}
	dir := CgroupDir(base, os.Getpid())
	return dir, inHostCgroupNS(func() error {
		if !force {
			// In the host cgroup namespace, /proc/self/cgroup is relative
			// to the host root, which is where root points.
			b, err := os.ReadFile("/proc/thread-self/cgroup")
			if err != nil {
				return fmt.Errorf("reading own cgroup: %w", err)
			}
			path := ""
			for _, line := range strings.Split(strings.TrimSpace(string(b)), "\n") {
				if p, ok := strings.CutPrefix(line, "0::"); ok {
					path = p
				}
			}
			if !MemoryLimited(root, path) {
				return errCgroupNotNeeded
			}
		}
		if err := os.Mkdir(base, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("creating %s: %w", base, err)
		}
		// Children need the controllers delegated to set their limits.
		// Best effort: the base holds no processes, so this is allowed.
		_ = os.WriteFile(filepath.Join(base, "cgroup.subtree_control"), []byte("+memory +pids +cpu"), 0o644)
		// Remove children left by gatekeepers that are gone; rmdir fails
		// on a cgroup that still has processes, which is what we want.
		if entries, err := os.ReadDir(base); err == nil {
			for _, e := range entries {
				if e.IsDir() {
					_ = unix.Rmdir(filepath.Join(base, e.Name()))
				}
			}
		}
		if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
			return fmt.Errorf("creating %s: %w", dir, err)
		}
		for _, l := range cgroupLimits {
			if err := os.WriteFile(filepath.Join(dir, l.file), []byte(l.value), 0o644); err != nil {
				logf("setting %s: %s", l.file, err)
			}
		}
		// "0" is the writing process; cgroup.procs moves all its threads.
		if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("0"), 0o644); err != nil {
			_ = unix.Rmdir(dir)
			return fmt.Errorf("moving into %s: %w", dir, err)
		}
		return nil
	})
}

// inHostCgroupNS runs fn on a locked thread that joined the host cgroup
// namespace (see joinCgroup). The thread is discarded afterwards.
func inHostCgroupNS(fn func() error) error {
	errc := make(chan error, 1)
	go func() {
		// No UnlockOSThread: the runtime discards this thread, and its
		// cgroup namespace, when the goroutine exits.
		runtime.LockOSThread()
		self, err1 := os.Readlink("/proc/thread-self/ns/cgroup")
		host, err2 := os.Readlink("/proc/1/ns/cgroup")
		if err1 == nil && err2 == nil && self != host {
			fd, err := unix.Open("/proc/1/ns/cgroup", unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err != nil {
				errc <- fmt.Errorf("opening host cgroup namespace: %w", err)
				return
			}
			err = unix.Setns(fd, unix.CLONE_NEWCGROUP)
			unix.Close(fd)
			if err != nil {
				errc <- fmt.Errorf("joining host cgroup namespace: %w", err)
				return
			}
		}
		errc <- fn()
	}()
	return <-errc
}

// leaveCgroup removes our own cgroup on a normal exit: the parent may exit
// without waiting for us (a CLI on Ctrl-C), so nobody else would. A cgroup
// cannot be removed while it holds a process, so move to the root cgroup
// first, which accepts processes. A gatekeeper that is killed leaves its
// directory to the next one's sweep.
func leaveCgroup(dir string) {
	root := filepath.Dir(filepath.Dir(dir))
	err := inHostCgroupNS(func() error {
		if err := os.WriteFile(filepath.Join(root, "cgroup.procs"), []byte("0"), 0o644); err != nil {
			return err
		}
		return unix.Rmdir(dir)
	})
	if err != nil {
		logf("removing %s: %s", dir, err)
	}
}

// Run is the gatekeeper process main loop. It returns the exit code.
func Run() int {
	// Keep this process small and independent of the parent's runtime
	// settings.
	runtime.GOMAXPROCS(1)
	_ = unix.SetNonblock(2, true)
	// Started from a memfd, the process would be named after its fd number.
	if name, err := unix.BytePtrFromString("ig-gatekeeper"); err == nil {
		_ = unix.Prctl(unix.PR_SET_NAME, uintptr(unsafe.Pointer(name)), 0, 0, 0)
	}

	var bounds [2]int64
	for group, env := range [2]string{BoundRuntimeEnv, BoundPidFileEnv} {
		b, err := strconv.ParseInt(os.Getenv(env), 10, 64)
		if err != nil || b <= 0 {
			b = int64(defaultBound)
		}
		bounds[group] = b
	}
	recordSize, err := strconv.Atoi(os.Getenv(RecordSizeEnv))
	if err != nil || recordSize < 0 {
		recordSize = 0
	}
	closeInheritedFanotifyGroups()
	raiseNofile()

	s := &state{
		bounds:     bounds,
		sock:       FdSock,
		records:    -1,
		recordSize: recordSize,
		msg:        make([]byte, HeaderLen+recordSize+256),
		oob:        unix.UnixRights(0),
	}
	if _, err := unix.FcntlInt(FdRecords, unix.F_GETFD, 0); err == nil && recordSize > 0 {
		s.records = FdRecords
		// The kernel copies the map's value_size bytes here; the parent
		// checked it equals recordSize.
		s.bpfAttr = bpfMapElemAttr{mapFd: uint32(FdRecords), value: unsafe.Pointer(&s.msg[HeaderLen])}
	}
	// Room for bursts (each runtime event carries its ~5 KiB eBPF record):
	// with the default buffer a busy-but-healthy parent would hit the
	// "socket full → allow now" path during a deploy burst and miss
	// containers. FORCE needs CAP_NET_ADMIN; fall back to the capped size.
	if err := unix.SetsockoptInt(FdSock, unix.SOL_SOCKET, unix.SO_SNDBUFFORCE, sndBuf); err != nil {
		_ = unix.SetsockoptInt(FdSock, unix.SOL_SOCKET, unix.SO_SNDBUF, sndBuf)
	}
	binary.NativeEndian.PutUint32(s.resp[4:], unix.FAN_ALLOW)

	readyFlags := uint8(0)
	readyInfo := ""
	movedTo := ""
	if base := os.Getenv(CgroupEnv); base != "" {
		dir, err := joinCgroup(base, os.Getenv(CgroupForceEnv) == "1")
		if errors.Is(err, errCgroupNotNeeded) {
			readyFlags |= FlagCgroupNotNeeded
			readyInfo = err.Error()
		} else if err != nil {
			readyInfo = err.Error()
		} else {
			readyFlags |= FlagCgroupMoved
			readyInfo = dir
			movedTo = dir
		}
	}
	if !s.sendReady(readyFlags, readyInfo) {
		return 1
	}

	s.pollFds[0] = unix.PollFd{Fd: FdRuntime, Events: unix.POLLIN}
	s.pollFds[1] = unix.PollFd{Fd: FdPidFile, Events: unix.POLLIN}
	s.pollFds[2] = unix.PollFd{Fd: FdSock, Events: unix.POLLIN}

	logf("started (pid %d, bounds: runtime-binary %s, pid-file %s)",
		os.Getpid(), time.Duration(bounds[GroupRuntime]), time.Duration(bounds[GroupPidFile]))
	s.loop()
	s.allowAll()
	s.report(true)
	if movedTo != "" {
		leaveCgroup(movedTo)
	}
	runtime.KeepAlive(s)
	return 0
}

func (s *state) sendReady(flags uint8, info string) bool {
	clear(s.msg[:HeaderLen])
	binary.NativeEndian.PutUint32(s.msg[0:], ProtocolVersion)
	s.msg[4] = GroupReady
	s.msg[5] = flags
	n := copy(s.msg[HeaderLen:], info)
	if err := unix.Sendmsg(s.sock, s.msg[:HeaderLen+n], nil, nil, unix.MSG_NOSIGNAL); err != nil {
		logf("sending ready: %s", err)
		return false
	}
	return true
}

func (s *state) loop() {
	for {
		timeout := -1
		if s.nActive > 0 {
			timeout = int(time.Duration(s.nextDeadline()-now()) / time.Millisecond)
			if timeout < 0 {
				timeout = 0
			}
			timeout++ // round up, so we wake after the deadline
		}
		for i := range s.pollFds {
			s.pollFds[i].Revents = 0
		}
		if _, err := unix.Poll(s.pollFds[:], timeout); err != nil && err != unix.EINTR {
			logf("poll: %s", err)
			return
		}
		// Parent gone or socket closed: answer everything and exit. Our
		// fanotify fds close with us; once the parent's copies are closed
		// too, the kernel drops the marks.
		if s.pollFds[2].Revents&(unix.POLLHUP|unix.POLLERR|unix.POLLNVAL) != 0 {
			return
		}
		if s.pollFds[2].Revents&unix.POLLIN != 0 {
			if !s.recvDone() {
				return
			}
		}
		if s.pollFds[0].Revents&unix.POLLIN != 0 {
			s.readEvent(FdRuntime, GroupRuntime)
		}
		if s.pollFds[1].Revents&unix.POLLIN != 0 {
			s.readEvent(FdPidFile, GroupPidFile)
		}
		// A broken group fd would make poll return at once forever. Exit:
		// the parent sees us go and closes the groups.
		if (s.pollFds[0].Revents|s.pollFds[1].Revents)&(unix.POLLERR|unix.POLLNVAL) != 0 {
			logf("fanotify fd error, exiting")
			return
		}
		s.expire(now())
		s.report(false)
	}
}

func (s *state) nextDeadline() int64 {
	next := int64(1<<63 - 1)
	for i := range s.pending {
		if s.pending[i].active && s.pending[i].deadline < next {
			next = s.pending[i].deadline
		}
	}
	return next
}

// release answers FAN_ALLOW for a pending event on the group it came from and
// closes our copy of its fd. The fd stays open until then so its number
// cannot be reused by another pending event of the same group.
func (s *state) release(slot *pendingEvent) {
	groupFd := FdRuntime
	if slot.group == GroupPidFile {
		groupFd = FdPidFile
	}
	binary.NativeEndian.PutUint32(s.resp[0:], uint32(slot.fd))
	// ENOENT: the waiting process went away; nothing to answer.
	_, _ = unix.Write(groupFd, s.resp[:])
	unix.Close(int(slot.fd))
	slot.active = false
	s.nActive--
}

func (s *state) readEvent(fd int, group uint8) {
	n, err := unix.Read(fd, s.meta[:])
	if err != nil || n < metadataSize {
		return
	}
	mask := binary.NativeEndian.Uint64(s.meta[8:16])
	efd := int32(binary.NativeEndian.Uint32(s.meta[16:20]))
	pid := int32(binary.NativeEndian.Uint32(s.meta[20:24]))

	flags := uint8(0)
	msgLen := HeaderLen
	if group == GroupRuntime {
		// The eBPF program pushed exactly one record when this event was
		// dequeued; take it now to stay in lockstep with ig_fa_records.
		flags |= FlagHasRecord
		msgLen += s.recordSize
		if s.records >= 0 && s.lookupAndDeleteRecord() {
			flags |= FlagRecordOK
		}
	}

	s.seq++
	seq := s.seq
	perm := efd >= 0 && IsPermMask(mask)
	if perm {
		slot := &s.pending[seq%Slots]
		if slot.active {
			// Wrapped around a still-pending event: allow it first.
			s.release(slot)
			s.evicted++
		}
		*slot = pendingEvent{active: true, group: group, seq: seq, fd: efd, deadline: now() + s.bounds[group]}
		s.nActive++
	}

	binary.NativeEndian.PutUint32(s.msg[0:], seq)
	s.msg[4] = group
	if efd >= 0 {
		flags |= FlagHasFd
	}
	s.msg[5] = flags
	binary.NativeEndian.PutUint64(s.msg[8:], mask)
	binary.NativeEndian.PutUint32(s.msg[16:], uint32(pid))

	var oob []byte
	if efd >= 0 {
		// Patch the fd into the preallocated SCM_RIGHTS message.
		binary.NativeEndian.PutUint32(s.oob[unix.CmsgLen(0):], uint32(efd))
		oob = s.oob
	}
	// Never block on the parent: if it is not draining the socket, fail open.
	err = unix.Sendmsg(s.sock, s.msg[:msgLen], oob, nil, unix.MSG_DONTWAIT|unix.MSG_NOSIGNAL)
	if err != nil {
		s.dropped++
		if perm {
			s.release(&s.pending[seq%Slots])
		} else if efd >= 0 {
			unix.Close(int(efd))
		}
		return
	}
	s.forwarded++
	if !perm && efd >= 0 {
		// The parent got its own copy; ours is not needed for a response.
		unix.Close(int(efd))
	}
}

func (s *state) lookupAndDeleteRecord() bool {
	_, _, errno := unix.Syscall(unix.SYS_BPF, bpfMapLookupAndDeleteElem,
		uintptr(unsafe.Pointer(&s.bpfAttr)), unsafe.Sizeof(s.bpfAttr))
	return errno == 0
}

// recvDone drains "done" replies. It returns false when the parent is gone.
func (s *state) recvDone() bool {
	for {
		n, _, _, _, err := unix.Recvmsg(s.sock, s.done[:], nil, unix.MSG_DONTWAIT)
		if err == unix.EAGAIN || err == unix.EINTR {
			return true
		}
		if err != nil || n == 0 {
			return false
		}
		for off := 0; off+DoneLen <= n; off += DoneLen {
			seq := binary.NativeEndian.Uint32(s.done[off:])
			slot := &s.pending[seq%Slots]
			if slot.active && slot.seq == seq {
				s.release(slot)
				s.answered++
			}
		}
	}
}

func (s *state) expire(now int64) {
	if s.nActive == 0 {
		return
	}
	for i := range s.pending {
		if s.pending[i].active && s.pending[i].deadline <= now {
			s.release(&s.pending[i])
			s.expired++
		}
	}
}

func (s *state) allowAll() {
	for i := range s.pending {
		if s.pending[i].active {
			s.release(&s.pending[i])
			s.expired++
		}
	}
}

// report logs counters when the fail-open ones changed, at most every 10s.
func (s *state) report(force bool) {
	now := now()
	if !force && time.Duration(now-s.lastReport) < 10*time.Second {
		return
	}
	cur := [4]uint64{s.expired, s.dropped, s.evicted, s.forwarded}
	if !force && cur[0] == s.reported[0] && cur[1] == s.reported[1] && cur[2] == s.reported[2] {
		return
	}
	s.lastReport = now
	logf("fail-open: expired=%d dropped=%d evicted=%d (forwarded=%d answered=%d)",
		s.expired-s.reported[0], s.dropped-s.reported[1], s.evicted-s.reported[2], s.forwarded, s.answered)
	s.reported = cur
}
