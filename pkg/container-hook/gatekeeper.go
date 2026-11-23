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

package containerhook

// Fanotify permission events are answered from a separate process, the
// gatekeeper (package gatekeeper).
//
// Permission events have no kernel-side timeout: a runc exec (or pid-file
// access) blocks in fanotify_get_response until the reader answers. When the
// reader is a large process that is alive but cannot make progress (throttled
// in memcg reclaim, CPU-starved, a handler stuck on a slow dependency, or
// stopped), every container start, stop and exec on the host blocks, kubelet
// cannot restart the process through the same runtime, and the node freezes
// while still reporting Ready.
//
// An in-process watchdog does not help: under memcg throttling the threads
// holding the Go scheduler's Ps are themselves throttled, so no goroutine runs
// (observed with GOMAXPROCS=2 from a 200m CPU limit). The answer therefore
// has to come from another process.
//
// The gatekeeper is the only reader of both fanotify groups. For each event it
// dequeues the matching eBPF record (runtime group), then forwards the event
// to this process over a SOCK_SEQPACKET socket, passing the event fd with
// SCM_RIGHTS. We process it exactly as before and reply "done"; the
// gatekeeper then answers FAN_ALLOW. If we do not reply within the bound, or
// the socket is full, the gatekeeper allows on its own. It never waits on us
// and allocates nothing per event, so it keeps answering while we are stuck.
//
// The gatekeeper runs the dedicated small binary (cmd/container-hook-gatekeeper)
// when it is installed, or else this binary re-executed: init() below diverts
// it into gatekeeper.Run before main, so embedders work unchanged (at the
// cost of the embedder's package initialization in that process).
//
// Failing open loses detection for the affected containers; it never denies.
// That is the intended trade: a missed container is recoverable, a frozen
// node is not.

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"github.com/s3rj1k/go-fanotify/fanotify"
	log "github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/container-hook/gatekeeper"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/host"
)

const (
	// gatekeeperDisableEnv makes this process read and answer the fanotify
	// groups itself, without a deadline (the behavior before the
	// gatekeeper). Escape hatch only.
	gatekeeperDisableEnv = "IG_CONTAINER_HOOK_GATEKEEPER_DISABLE"
	// gatekeeperBinEnv overrides the path of the dedicated gatekeeper binary.
	gatekeeperBinEnv = "IG_CONTAINER_HOOK_GATEKEEPER_BIN"
	// defaultGatekeeperBin is where images ship the dedicated binary.
	defaultGatekeeperBin = "/usr/bin/ig-container-hook-gatekeeper"
	// gatekeeperCgroupEnv overrides the cgroup v2 directory the gatekeeper
	// runs in; "none" keeps it in our cgroup. Default: defaultGatekeeperCgroup
	// under the host's cgroup v2 root.
	gatekeeperCgroupEnv     = "IG_CONTAINER_HOOK_GATEKEEPER_CGROUP_DIR"
	defaultGatekeeperCgroup = "ig-container-hook-gatekeeper"

	defaultPermResponseBound = time.Second
	// The pid-file event holds create→start while the AddContainer callback
	// (collection add, enrichment) runs, so it gets more room by default.
	defaultPidFileResponseBound = 3 * time.Second
	minPermResponseBound        = 100 * time.Millisecond
	maxPermResponseBound        = 60 * time.Second
)

var recordSize = int(unsafe.Sizeof(execruntimeRecord{}))

var (
	configuredPermResponseBound    atomic.Int64
	configuredPidFileResponseBound atomic.Int64
)

func validateBound(bound time.Duration) error {
	if bound < minPermResponseBound || bound > maxPermResponseBound {
		return fmt.Errorf("permission response bound must be in [%s, %s]: %s",
			minPermResponseBound, maxPermResponseBound, bound)
	}
	return nil
}

// SetPermissionResponseBound sets how long a container runtime exec may wait
// for the container hook before the gatekeeper allows it on its own. It must be
// called before starting container collection.
func SetPermissionResponseBound(bound time.Duration) error {
	if err := validateBound(bound); err != nil {
		return err
	}
	configuredPermResponseBound.Store(int64(bound))
	return nil
}

// SetPidFileResponseBound sets how long container create→start may wait for
// the container hook (which runs the AddContainer callback meanwhile) before
// the gatekeeper allows it on its own. It must be called before starting
// container collection.
func SetPidFileResponseBound(bound time.Duration) error {
	if err := validateBound(bound); err != nil {
		return err
	}
	configuredPidFileResponseBound.Store(int64(bound))
	return nil
}

// PermissionResponseBound returns the bound for runtime-binary events (see
// SetPermissionResponseBound).
func PermissionResponseBound() time.Duration {
	if b := configuredPermResponseBound.Load(); b != 0 {
		return time.Duration(b)
	}
	return defaultPermResponseBound
}

// PidFileResponseBound returns the bound for pid-file events (see
// SetPidFileResponseBound).
func PidFileResponseBound() time.Duration {
	if b := configuredPidFileResponseBound.Load(); b != 0 {
		return time.Duration(b)
	}
	return defaultPidFileResponseBound
}

func init() {
	if os.Getenv(gatekeeper.Env) == "1" {
		os.Exit(gatekeeper.Run())
	}
}

// gkEvent is an event the gatekeeper forwarded. data.Fd is our own copy of
// the event fd (or -1).
type gkEvent struct {
	seq       uint32
	data      *fanotify.EventMetadata
	record    execruntimeRecord
	recordErr error
}

var errNoRecord = errors.New("no eBPF record for this event")

const (
	// gkChanDepth is how many forwarded events per group may wait for the
	// watcher. Past it, receive drops the event (the gatekeeper allows it at
	// its deadline): receive must never block, or it would stop noticing
	// that the gatekeeper is gone.
	gkChanDepth = 1024
	// gkReadyTimeout bounds the gatekeeper's startup (its cgroup move, or an
	// embedder's package initialization when re-executing ourselves).
	gkReadyTimeout = 30 * time.Second
	// gkExitTimeout bounds each wait for the gatekeeper to exit on close.
	gkExitTimeout = 5 * time.Second
)

type gatekeeperProc struct {
	cmd *exec.Cmd
	// sock never changes. It is closed only once receive has returned (or
	// never ran), so no goroutine uses a closed, possibly reused, fd number.
	sock       int
	sockClosed bool // guarded by sendMu
	receiving  atomic.Bool
	recvDone   chan struct{}
	// cgroupDir is the gatekeeper's own cgroup, set by waitReady and removed
	// once the process exited.
	cgroupDir atomic.Pointer[string]

	runtimeCh chan *gkEvent
	pidCh     chan *gkEvent
	dropped   atomic.Uint64

	sendMu    sync.Mutex
	closeOnce sync.Once
	exited    chan struct{}
}

// gatekeeperCgroup returns the cgroup v2 base directory for gatekeepers, or "".
// It must not be our own memcg: see gatekeeper.joinCgroup.
func gatekeeperCgroup() string {
	switch v := os.Getenv(gatekeeperCgroupEnv); v {
	case "none":
		return ""
	case "":
		return filepath.Join(host.HostRoot, "sys/fs/cgroup", defaultGatekeeperCgroup)
	default:
		return v
	}
}

func gatekeeperBinary() string {
	if p := os.Getenv(gatekeeperBinEnv); p != "" {
		return p
	}
	if st, err := os.Stat(defaultGatekeeperBin); err == nil && st.Mode().IsRegular() && st.Mode()&0o111 != 0 {
		return defaultGatekeeperBin
	}
	return "/proc/self/exe"
}

// dupCloexec duplicates fd with O_CLOEXEC, so the only copy the gatekeeper
// inherits is the one exec.Cmd places at its ExtraFiles position.
func dupCloexec(fd int, name string) (*os.File, error) {
	dup, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("dup %s fd: %w", name, err)
	}
	return os.NewFile(uintptr(dup), name), nil
}

// startGatekeeper starts the gatekeeper for the two fanotify groups and waits
// until it is ready to read them. recordsFd may be -1; otherwise
// recordsValueSize is the map's value size, which must match the record type.
func startGatekeeper(runtimeFd, pidFd, recordsFd int, recordsValueSize int, runtimeBound, pidFileBound time.Duration) (*gatekeeperProc, error) {
	if recordsFd >= 0 && recordsValueSize != recordSize {
		// The gatekeeper reads value_size bytes into a recordSize buffer.
		return nil, fmt.Errorf("ig_fa_records value size %d differs from the record type (%d)", recordsValueSize, recordSize)
	}
	fds, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_SEQPACKET|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, fmt.Errorf("socketpair: %w", err)
	}
	parentSock := fds[0]
	child := os.NewFile(uintptr(fds[1]), "gatekeeper-sock")
	defer child.Close()

	// Order must match gatekeeper.Fd*.
	files := make([]*os.File, 0, 4)
	defer func() {
		for _, f := range files {
			if f != child {
				f.Close()
			}
		}
	}()
	for _, src := range []struct {
		fd   int
		name string
	}{{runtimeFd, "fanotify-runtime"}, {pidFd, "fanotify-pidfile"}} {
		f, err := dupCloexec(src.fd, src.name)
		if err != nil {
			unix.Close(parentSock)
			return nil, err
		}
		files = append(files, f)
	}
	files = append(files, child)
	size := 0
	if recordsFd >= 0 {
		f, err := dupCloexec(recordsFd, "ig_fa_records")
		if err != nil {
			unix.Close(parentSock)
			return nil, err
		}
		files = append(files, f)
		size = recordSize
	}

	// The gatekeeper logs to a pipe of its own, which it writes without
	// blocking; sharing our stderr could block it on a full log pipe.
	logR, logW, err := os.Pipe()
	if err != nil {
		unix.Close(parentSock)
		return nil, fmt.Errorf("log pipe: %w", err)
	}
	defer logW.Close()

	bin := gatekeeperBinary()
	if bin == "/proc/self/exe" {
		log.Warnf("container-hook: %s not found; the gatekeeper re-executes this binary, which runs its package initialization in the gatekeeper and charges that memory to this process's cgroup. Ship cmd/container-hook-gatekeeper as %s", defaultGatekeeperBin, defaultGatekeeperBin)
	}
	base := gatekeeperCgroup()
	cmd := exec.Command(bin)
	cmd.Env = append(os.Environ(),
		gatekeeper.Env+"=1",
		gatekeeper.BoundRuntimeEnv+"="+strconv.FormatInt(int64(runtimeBound), 10),
		gatekeeper.BoundPidFileEnv+"="+strconv.FormatInt(int64(pidFileBound), 10),
		gatekeeper.RecordSizeEnv+"="+strconv.Itoa(size),
		gatekeeper.CgroupEnv+"="+base)
	cmd.ExtraFiles = files
	cmd.Stdout = logW
	cmd.Stderr = logW
	// No Pdeathsig: it follows the thread that forked, not this process
	// (golang/go#27505). The gatekeeper exits when the socket closes, which
	// is what happens when we die.
	if err := cmd.Start(); err != nil {
		unix.Close(parentSock)
		logR.Close()
		return nil, fmt.Errorf("starting gatekeeper %s: %w", cmd.Path, err)
	}
	// Only the gatekeeper keeps the child ends: if it exits early, waitReady
	// sees EOF instead of waiting for the timeout.
	child.Close()
	logW.Close()
	go relayGatekeeperLog(logR)

	g := &gatekeeperProc{
		cmd:       cmd,
		sock:      parentSock,
		runtimeCh: make(chan *gkEvent, gkChanDepth),
		pidCh:     make(chan *gkEvent, gkChanDepth),
		exited:    make(chan struct{}),
		recvDone:  make(chan struct{}),
	}
	go func() {
		_ = cmd.Wait()
		if dir := g.cgroupDir.Load(); dir != nil {
			_ = unix.Rmdir(*dir)
		}
		close(g.exited)
	}()

	if err := g.waitReady(); err != nil {
		g.kill()
		return nil, err
	}
	return g, nil
}

// waitReady reads the gatekeeper's ready message: protocol version and where
// it runs. Until it arrives nobody reads the fanotify groups, so no mark may
// be added before.
func (g *gatekeeperProc) waitReady() error {
	tv := unix.NsecToTimeval(int64(gkReadyTimeout))
	_ = unix.SetsockoptTimeval(g.sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &tv)
	defer func() {
		zero := unix.Timeval{}
		_ = unix.SetsockoptTimeval(g.sock, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &zero)
	}()
	buf := make([]byte, gatekeeper.HeaderLen+256)
	for {
		n, _, _, _, err := unix.Recvmsg(g.sock, buf, nil, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return fmt.Errorf("waiting for the gatekeeper to be ready: %w", err)
		}
		if n == 0 {
			return errors.New("gatekeeper exited before it was ready")
		}
		if n < gatekeeper.HeaderLen || buf[4] != gatekeeper.GroupReady {
			return errors.New("gatekeeper did not start with a ready message")
		}
		if v := binary.NativeEndian.Uint32(buf[0:]); v != gatekeeper.ProtocolVersion {
			return fmt.Errorf("gatekeeper %s speaks protocol %d, want %d", g.cmd.Path, v, gatekeeper.ProtocolVersion)
		}
		info := string(buf[gatekeeper.HeaderLen:n])
		if buf[5]&gatekeeper.FlagCgroupMoved != 0 {
			g.cgroupDir.Store(&info)
			log.Infof("container-hook: gatekeeper runs in cgroup %s", info)
		} else if info != "" {
			log.Warnf("container-hook: gatekeeper could not leave this process's cgroup, so memory pressure here can still stall it: %s", info)
		}
		return nil
	}
}

func relayGatekeeperLog(r *os.File) {
	defer r.Close()
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		log.Info(sc.Text())
	}
}

// watchExit calls onLost if the gatekeeper exits before close. This, not the
// socket, is how its loss is noticed: a socket EOF only arrives after every
// message still queued, which can take as long as the stall we are bounding.
func (g *gatekeeperProc) watchExit(stop <-chan bool, onLost func(error)) {
	select {
	case <-g.exited:
		onLost(fmt.Errorf("gatekeeper exited: %s", g.cmd.ProcessState))
	case <-stop:
	}
}

// receive forwards gatekeeper events to the per-group channels until the
// socket is closed. It never blocks on the channels: a full one means the
// watcher is far behind, so the event is dropped and the gatekeeper allows it
// at its deadline.
func (g *gatekeeperProc) receive() {
	defer close(g.recvDone)
	defer close(g.runtimeCh)
	defer close(g.pidCh)

	buf := make([]byte, gatekeeper.HeaderLen+recordSize)
	oob := make([]byte, unix.CmsgSpace(4*4))
	for {
		n, oobn, _, _, err := unix.Recvmsg(g.sock, buf, oob, unix.MSG_CMSG_CLOEXEC)
		if err == unix.EINTR {
			continue
		}
		if err != nil || n == 0 {
			return
		}
		fd := int32(-1)
		if oobn > 0 {
			if msgs, err := unix.ParseSocketControlMessage(oob[:oobn]); err == nil {
				for i := range msgs {
					fds, err := unix.ParseUnixRights(&msgs[i])
					if err != nil {
						continue
					}
					for _, f := range fds {
						if fd < 0 {
							fd = int32(f)
						} else {
							unix.Close(f)
						}
					}
				}
			}
		}
		if n < gatekeeper.HeaderLen || buf[5]&gatekeeper.FlagHasFd == 0 && fd >= 0 {
			// Malformed: never leak a received fd.
			if fd >= 0 {
				unix.Close(int(fd))
			}
			continue
		}
		ev := &gkEvent{seq: binary.NativeEndian.Uint32(buf[0:])}
		group := buf[4]
		flags := buf[5]
		ev.data = &fanotify.EventMetadata{FanotifyEventMetadata: unix.FanotifyEventMetadata{
			Event_len:    uint32(fanotifyEventMetadataSize),
			Vers:         unix.FANOTIFY_METADATA_VERSION,
			Metadata_len: uint16(fanotifyEventMetadataSize),
			Mask:         binary.NativeEndian.Uint64(buf[8:]),
			Fd:           fd,
			Pid:          int32(binary.NativeEndian.Uint32(buf[16:])),
		}}
		if flags&gatekeeper.FlagHasRecord != 0 {
			if flags&gatekeeper.FlagRecordOK != 0 && n >= gatekeeper.HeaderLen+recordSize {
				ev.record = *(*execruntimeRecord)(unsafe.Pointer(&buf[gatekeeper.HeaderLen]))
			} else {
				ev.recordErr = errNoRecord
			}
		}
		ch := g.pidCh
		if group == gatekeeper.GroupRuntime {
			ch = g.runtimeCh
		}
		select {
		case ch <- ev:
		default:
			closeEventFd(ev.data)
			if g.dropped.Add(1)%100 == 1 {
				log.Warnf("container-hook: watcher %d events behind; dropping forwarded events, the gatekeeper allows them at its deadline (dropped=%d)", gkChanDepth, g.dropped.Load())
			}
		}
	}
}

// startReceive runs receive in a goroutine, tracked by wg if not nil. The
// socket is not closed until it returned.
func (g *gatekeeperProc) startReceive(wg *sync.WaitGroup) {
	g.receiving.Store(true)
	if wg != nil {
		wg.Add(1)
	}
	go func() {
		if wg != nil {
			defer wg.Done()
		}
		g.receive()
	}()
}

// drain closes the fds of events left in the channels after the watchers
// stopped. The channels must be closed (receive returned).
func (g *gatekeeperProc) drain() {
	for _, ch := range []chan *gkEvent{g.runtimeCh, g.pidCh} {
		for ev := range ch {
			closeEventFd(ev.data)
		}
	}
}

// done tells the gatekeeper we finished with an event, so it can be allowed
// now. A late or failed reply is harmless: the gatekeeper has already allowed
// the event on its own.
func (g *gatekeeperProc) done(seq uint32) {
	var b [gatekeeper.DoneLen]byte
	binary.NativeEndian.PutUint32(b[:], seq)
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	if !g.sockClosed {
		_, _ = unix.Write(g.sock, b[:])
	}
}

// close makes the gatekeeper allow everything pending and exit, and makes
// receive return. Idempotent.
func (g *gatekeeperProc) close() {
	g.closeOnce.Do(func() {
		_ = unix.Shutdown(g.sock, unix.SHUT_RDWR)
		g.waitExit()
		g.closeSock()
	})
}

// kill stops a gatekeeper that never became ready.
func (g *gatekeeperProc) kill() {
	g.closeOnce.Do(func() {
		_ = g.cmd.Process.Kill()
		g.waitExit()
		g.closeSock()
	})
}

// closeSock closes the socket once receive no longer uses it. The socket must
// already be shut down, which makes a running receive return at once.
func (g *gatekeeperProc) closeSock() {
	if g.receiving.Load() {
		<-g.recvDone
	}
	g.sendMu.Lock()
	defer g.sendMu.Unlock()
	if !g.sockClosed {
		unix.Close(g.sock)
		g.sockClosed = true
	}
}

// waitExit waits for the gatekeeper to exit, killing it if it does not, and
// gives up eventually: a process stuck in the kernel must not hang Close.
func (g *gatekeeperProc) waitExit() {
	select {
	case <-g.exited:
		return
	case <-time.After(gkExitTimeout):
	}
	_ = g.cmd.Process.Kill()
	select {
	case <-g.exited:
	case <-time.After(gkExitTimeout):
		log.Errorf("container-hook: %s did not exit after SIGKILL", g)
	}
}

func gatekeeperDisabled() bool {
	v := os.Getenv(gatekeeperDisableEnv)
	return v == "1" || v == "true"
}

func (g *gatekeeperProc) String() string {
	if g == nil || g.cmd == nil || g.cmd.Process == nil {
		return "gatekeeper(none)"
	}
	return fmt.Sprintf("gatekeeper(pid %d, %s)", g.cmd.Process.Pid, g.cmd.Path)
}
