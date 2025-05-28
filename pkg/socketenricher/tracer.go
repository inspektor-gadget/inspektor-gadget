// Copyright 2022 The Inspektor Gadget authors
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

package socketenricher

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/btfgen"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/kallsyms"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketenricher ./bpf/socket-enricher.bpf.c -- -I./bpf/

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -cc clang -cflags ${CFLAGS} socketsiter ./bpf/sockets-iter.bpf.c -- -I./bpf/

const (
	SocketsMapName = "gadget_sockets"
)

// SocketEnricher creates a map exposing processes owning each socket.
//
// This makes it possible for network gadgets to access that information and
// display it directly from the BPF code. Example of such code in the dns and
// sni gadgets.
type SocketEnricher struct {
	objs     socketenricherObjects
	objsIter socketsiterObjects
	links    []link.Link

	closeOnce sync.Once
	done      chan bool
}

func (se *SocketEnricher) SocketsMap() *ebpf.Map {
	return se.objs.GadgetSockets
}

func NewSocketEnricher() (*SocketEnricher, error) {
	se := &SocketEnricher{}

	if err := se.start(); err != nil {
		se.Close()
		return nil, err
	}

	return se, nil
}

func findCgroupPath() string {
	paths := []string{
		"/sys/fs/cgroup",
		"/sys/fs/cgroup/unified",
		"/sys/fs/cgroup/system.slice",
	}

	for _, path := range paths {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}
	log.Fatal("Could not find cgroup path")
	return ""
}

func (se *SocketEnricher) start() error {
	specIter, err := loadSocketsiter()
	if err != nil {
		return fmt.Errorf("loading socketsiter asset: %w", err)
	}

	err = kallsyms.SpecUpdateAddresses(specIter, []string{"socket_file_ops"})
	if err != nil {
		// Being unable to access to /proc/kallsyms can be caused by not having
		// CAP_SYSLOG.
		log.Warnf("updating socket_file_ops address with ksyms: %v\nEither you cannot access /proc/kallsyms or this file does not contain socket_file_ops", err)
	}

	opts := ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			KernelTypes: btfgen.GetBTFSpec(),
		},
	}

	disableBPFIterators := false
	if err := specIter.LoadAndAssign(&se.objsIter, nil); err != nil {
		disableBPFIterators = true
		log.Warnf("Socket enricher: skip loading iterators: %v", err)
	}

	spec, err := loadSocketenricher()
	if err != nil {
		return fmt.Errorf("loading socket enricher asset: %w", err)
	}

	if disableBPFIterators {
		socketSpec := &socketenricherSpecs{}
		if err := spec.Assign(socketSpec); err != nil {
			return err
		}
		if err := socketSpec.DisableBpfIterators.Set(true); err != nil {
			return err
		}
	} else {
		opts.MapReplacements = map[string]*ebpf.Map{
			SocketsMapName: se.objsIter.GadgetSockets,
		}
	}

	if err := spec.LoadAndAssign(&se.objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			fmt.Printf("Socket enricher: %+v\n", ve)
		}
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	var l link.Link

	cgroupPath := findCgroupPath()

	l, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCGroupInetSockCreate,
		Program: se.objs.CgroupSockCreate,
	})
	if err != nil {
		return err
	}
	se.links = append(se.links, l)

	l, err = link.AttachCgroup(link.CgroupOptions{
		Path:    cgroupPath,
		Attach:  ebpf.AttachCgroupInetSockRelease,
		Program: se.objs.CgroupSockRelease,
	})
	if err != nil {
		return err
	}
	se.links = append(se.links, l)

	if !disableBPFIterators {
		// get initial sockets
		socketsIter, err := link.AttachIter(link.IterOptions{
			Program: se.objsIter.IgSocketsIt,
		})
		if err != nil {
			return fmt.Errorf("attach BPF iterator: %w", err)
		}
		defer socketsIter.Close()

		_, err = bpfiterns.Read(socketsIter)
		if err != nil {
			return fmt.Errorf("read BPF iterator: %w", err)
		}

		//		// Schedule socket cleanup
		//		cleanupIter, err := link.AttachIter(link.IterOptions{
		//			Program: se.objsIter.IgSkCleanup,
		//			Map:     se.objsIter.GadgetSockets,
		//		})
		//		if err != nil {
		//			return fmt.Errorf("attach BPF iterator for cleanups: %w", err)
		//		}
		//		se.links = append(se.links, cleanupIter)
		//
		//		se.done = make(chan bool)
		//		go se.cleanupDeletedSockets(cleanupIter)
	}

	return nil
}

func (se *SocketEnricher) cleanupDeletedSockets(cleanupIter *link.Iter) {
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-se.done:
			return
		case <-ticker.C:
			err := se.cleanupDeletedSocketsNow(cleanupIter)
			if err != nil {
				fmt.Printf("socket enricher: %v\n", err)
			}
		}
	}
}

func (se *SocketEnricher) cleanupDeletedSocketsNow(cleanupIter *link.Iter) error {
	// No need to change pidns for this iterator because cleanupIter is an
	// iterator on a map, not on tasks.
	_, err := bpfiterns.ReadOnCurrentPidNs(cleanupIter)
	return err
}

func (se *SocketEnricher) Close() {
	se.closeOnce.Do(func() {
		if se.done != nil {
			close(se.done)
		}
	})

	for _, l := range se.links {
		gadgets.CloseLink(l)
	}
	se.links = nil
	se.objs.Close()
	se.objsIter.Close()
}
