// Copyright 2023 The Inspektor Gadget authors
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

import (
	"errors"
	"fmt"
	"os"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"golang.org/x/sys/unix"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} -no-global-types privatedata ./bpf/privatedata.bpf.c -- -I./bpf/

// readPrivateDataFromFd use ebpf to read the private_data pointer from the
// kernel "struct file" associated with the given fd.
//
// It can then be used in other ebpf programs.
//
// This is done:
//   - without using bpf iterators in order to work on old kernels.
//   - without comparing pids from userspace and ebpf in order to work from
//     different pid namespaces.
func readPrivateDataFromFd(fd int) (uint64, error) {
	var objs privatedataObjects
	var links []link.Link
	var err error
	sock := [2]int{-1, -1}

	defer func() {
		for i := 0; i < 2; i++ {
			if sock[i] != -1 {
				unix.Close(sock[i])
			}
		}
		for _, l := range links {
			gadgets.CloseLink(l)
		}
		objs.Close()
	}()

	// Create a socket pair
	sock, err = unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		return 0, fmt.Errorf("creating socket pair: %w", err)
	}

	// Find the inode of the socket
	fdFileInfo, err := os.Stat(fmt.Sprintf("/proc/self/fd/%d", sock[0]))
	if err != nil {
		return 0, fmt.Errorf("reading file info from fd %d: %w", fd, err)
	}
	fdStat, ok := fdFileInfo.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, errors.New("not a syscall.Stat_t")
	}
	fdIno := fdStat.Ino

	// Load ebpf program configured with the socket inode
	spec, err := loadPrivatedata()
	if err != nil {
		return 0, fmt.Errorf("load ebpf program for container-hook: %w", err)
	}
	consts := map[string]interface{}{
		"socket_ino": uint64(fdIno),
	}
	if err := spec.RewriteConstants(consts); err != nil {
		return 0, fmt.Errorf("RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{}
	if err := spec.LoadAndAssign(&objs, &opts); err != nil {
		return 0, fmt.Errorf("loading maps and programs: %w", err)
	}

	// Attach ebpf programs
	l, err := link.Kprobe("__scm_send", objs.IgScmSndE, nil)
	if err != nil {
		return 0, fmt.Errorf("attaching kprobe __scm_send: %w", err)
	}
	links = append(links, l)

	l, err = link.Kretprobe("fget_raw", objs.IgFgetX, nil)
	if err != nil {
		return 0, fmt.Errorf("attaching kretprobe fget_raw: %w", err)
	}
	links = append(links, l)

	// Send the fd through the socket with SCM_RIGHTS.
	// This will trigger the __scm_send kprobe and fget_raw kretprobe
	buf := make([]byte, 1)
	err = unix.Sendmsg(sock[0], buf, unix.UnixRights(fd), nil, 0)
	if err != nil {
		return 0, fmt.Errorf("sending fd: %w", err)
	}

	// Read private_data from objs
	privateData := uint64(0)
	err = objs.IgPrivateData.Lookup(uint32(0), &privateData)
	if err != nil {
		return 0, fmt.Errorf("reading private_data: %w", err)
	}
	if privateData == 0 {
		return 0, fmt.Errorf("private_data is 0")
	}
	return privateData, nil
}
