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

package uprobetracer

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
)

// testState drives the injected uprobetracer seams so the refcount/attach
// bookkeeping can be exercised without a kernel or live containers.
type testState struct {
	currentInode uint64 // realInode that the next resolved file maps to
	openErr      error  // when set, openInContainer fails (e.g. non-ELF / missing)
	inodeErr     error  // when set, readRealInode fails
	attachErr    error  // when set, attachToFile fails (e.g. symbol absent)

	attachCount int        // number of real uprobe attaches performed
	openFiles   []*os.File // every file handed out, so the test can clean up
}

func (s *testState) open(_ uint32, _ string) (*os.File, error) {
	if s.openErr != nil {
		return nil, s.openErr
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		return nil, err
	}
	s.openFiles = append(s.openFiles, f)
	return f, nil
}

func (s *testState) readInode(_ int) (uint64, error) {
	if s.inodeErr != nil {
		return 0, s.inodeErr
	}
	return s.currentInode, nil
}

func (s *testState) attach(_ *os.File) (link.Link, error) {
	if s.attachErr != nil {
		return nil, s.attachErr
	}
	s.attachCount++
	// link.Link cannot be implemented outside cilium/ebpf (unexported method);
	// keeper.close() tolerates a nil link, so the attach count is the observable
	// signal for "how many uprobes were really attached".
	return nil, nil
}

// newTestTracer returns a tracer wired to the test seams, already in "running"
// mode (prog != nil) with an absolute attach path so searchForLibrary resolves
// to exactly one file whose realInode is controlled by testState.currentInode.
func newTestTracer(t *testing.T) (*Tracer[any], *testState) {
	t.Helper()
	tr, err := NewTracer[any](logger.DefaultLogger())
	if err != nil {
		t.Fatalf("NewTracer: %v", err)
	}
	st := &testState{}
	tr.prog = &ebpf.Program{} // sentinel: non-nil => running mode
	tr.progName = "test_ssl"
	tr.progType = ProgUprobe
	tr.attachFilePath = "/lib/libtest.so" // absolute => single resolved path
	tr.attachSymbol = "SSL_write"
	tr.openInContainer = st.open
	tr.readRealInode = st.readInode
	tr.attachToFile = st.attach
	t.Cleanup(func() {
		for _, f := range st.openFiles {
			f.Close()
		}
	})
	return tr, st
}

// testContainer builds a minimal Container whose ContainerPid() returns pid.
// A non-existent pid keeps the /proc/<pid>/exe guard from short-circuiting, so
// the dedup logic itself is exercised on every ReattachContainerPid.
func testContainer(pid uint32) *containercollection.Container {
	c := &containercollection.Container{}
	c.Runtime.ContainerPID = pid
	return c
}

const fakePid = uint32(4000000) // outside any real /proc range

func TestReattachIdempotentSameInode(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100

	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	for i := 0; i < 5; i++ {
		if err := tr.ReattachContainerPid(fakePid); err != nil {
			t.Fatalf("ReattachContainerPid #%d: %v", i, err)
		}
	}

	if st.attachCount != 1 {
		t.Errorf("attachCount = %d, want 1 (re-attach to same inode must not re-attach)", st.attachCount)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 1", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 1 || got[0] != 100 {
		t.Errorf("containerPid2Inodes[pid] = %v, want [100]", got)
	}
}

func TestReattachNewInodeAdds(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}

	// Process settles into a new binary at the same path -> new realInode.
	st.currentInode = 200
	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}

	if st.attachCount != 2 {
		t.Errorf("attachCount = %d, want 2 (new inode must attach)", st.attachCount)
	}
	if k := tr.inodeRefCount[200]; k == nil || k.counter != 1 {
		t.Errorf("inodeRefCount[200] = %+v, want counter 1", k)
	}
	if got := tr.containerPid2Inodes[fakePid]; len(got) != 2 {
		t.Errorf("containerPid2Inodes[pid] = %v, want 2 inodes (100,200)", got)
	}
}

func TestDetachAfterReattachNoLeak(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100
	if err := tr.AttachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("AttachContainer: %v", err)
	}
	st.currentInode = 200
	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}

	if err := tr.DetachContainer(testContainer(fakePid)); err != nil {
		t.Fatalf("DetachContainer: %v", err)
	}

	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount not empty after detach: %v (leak/over-ref)", tr.inodeRefCount)
	}
	if _, ok := tr.containerPid2Inodes[fakePid]; ok {
		t.Errorf("containerPid2Inodes still has pid after detach")
	}
	if _, ok := tr.containerPid2ExeTarget[fakePid]; ok {
		t.Errorf("containerPid2ExeTarget still has pid after detach")
	}
}

// An exec event for a pid that AttachContainer never recorded (e.g. the event
// raced DetachContainer and landed after teardown) must be a no-op: attaching
// fresh would install a uprobe link with no DetachContainer to ever release it.
func TestReattachUntrackedPidIsNoOp(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 300

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid on untracked pid: %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (untracked pid must not fresh-attach)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated for untracked pid: %v", tr.inodeRefCount)
	}
	if _, ok := tr.containerPid2Inodes[fakePid]; ok {
		t.Errorf("containerPid2Inodes added entry for untracked pid (would leak)")
	}
}

func TestReattachSkipsNonELF(t *testing.T) {
	tr, st := newTestTracer(t)
	st.openErr = errors.New("not an ELF / cannot open")

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (non-ELF open failure must be skipped)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated on skip: %v", tr.inodeRefCount)
	}
	if len(tr.containerPid2Inodes[fakePid]) != 0 {
		t.Errorf("containerPid2Inodes mutated on skip: %v", tr.containerPid2Inodes[fakePid])
	}
}

func TestReattachSkipsSymbolAbsent(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 500
	st.attachErr = errors.New("symbol SSL_write not found")

	if err := tr.ReattachContainerPid(fakePid); err != nil {
		t.Fatalf("ReattachContainerPid: %v", err)
	}
	if st.attachCount != 0 {
		t.Errorf("attachCount = %d, want 0 (attach itself failed)", st.attachCount)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount mutated when symbol absent: %v", tr.inodeRefCount)
	}
	if len(tr.containerPid2Inodes[fakePid]) != 0 {
		t.Errorf("containerPid2Inodes mutated when symbol absent: %v", tr.containerPid2Inodes[fakePid])
	}
}

func TestSharedInodeAcrossPidsRefcount(t *testing.T) {
	tr, st := newTestTracer(t)
	st.currentInode = 100 // both containers share the same image/inode

	pidA, pidB := fakePid, fakePid+1
	if err := tr.AttachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("AttachContainer A: %v", err)
	}
	if err := tr.AttachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("AttachContainer B: %v", err)
	}

	if st.attachCount != 1 {
		t.Errorf("attachCount = %d, want 1 (shared inode attaches once)", st.attachCount)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 2 {
		t.Errorf("inodeRefCount[100] = %+v, want counter 2", k)
	}

	if err := tr.DetachContainer(testContainer(pidA)); err != nil {
		t.Fatalf("DetachContainer A: %v", err)
	}
	if k := tr.inodeRefCount[100]; k == nil || k.counter != 1 {
		t.Errorf("after detach A: inodeRefCount[100] = %+v, want counter 1", k)
	}
	if err := tr.DetachContainer(testContainer(pidB)); err != nil {
		t.Fatalf("DetachContainer B: %v", err)
	}
	if len(tr.inodeRefCount) != 0 {
		t.Errorf("inodeRefCount not empty after both detached: %v", tr.inodeRefCount)
	}
}

func TestSettledExecutablePath(t *testing.T) {
	tr, _ := newTestTracer(t)

	// /proc/<self>/exe resolves to the running test binary (absolute).
	self := uint32(os.Getpid())
	if p, ok := tr.settledExecutablePath(self); !ok || !filepath.IsAbs(p) {
		t.Errorf("settledExecutablePath(self) = (%q, %v), want (absolute path, true)", p, ok)
	}

	// A non-existent pid has no /proc/<pid>/exe.
	if p, ok := tr.settledExecutablePath(fakePid); ok {
		t.Errorf("settledExecutablePath(fakePid) = (%q, true), want false", p)
	}
}

func TestReattachAfterCloseErrors(t *testing.T) {
	tr, _ := newTestTracer(t)
	tr.Close()
	if err := tr.ReattachContainerPid(fakePid); err == nil {
		t.Errorf("ReattachContainerPid after Close should error")
	}
}
