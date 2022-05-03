//go:build linux
// +build linux

// Copyright 2019-2022 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this bio except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package tracer

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"
	"unsafe"

	containercollection "github.com/kinvolk/inspektor-gadget/pkg/container-collection"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
	"github.com/kinvolk/inspektor-gadget/pkg/gadgets/biotop/types"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

// #include <linux/types.h>
// #include "./bpf/biotop.h"
import "C"

//go:generate sh -c "GOOS=$(go env GOHOSTOS) GOARCH=$(go env GOHOSTARCH) go run github.com/cilium/ebpf/cmd/bpf2go -target bpfel -cc clang biotop ./bpf/biotop.bpf.c -- -I./bpf/ -I../../.. -target bpf -D__TARGET_ARCH_x86"

type Config struct {
	TargetPid  int
	MaxRows    int
	Interval   time.Duration
	SortBy     types.SortBy
	MountnsMap *ebpf.Map
	Node       string
}

type Tracer struct {
	config           *Config
	objs             biotopObjects
	ioStartLink      link.Link
	startRequestLink link.Link
	doneLink         link.Link
	resolver         containercollection.ContainerResolver
	statsCallback    func([]types.Stats)
	errorCallback    func(error)
	done             chan bool
}

func NewTracer(config *Config, resolver containercollection.ContainerResolver,
	statsCallback func([]types.Stats), errorCallback func(error),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		resolver:      resolver,
		statsCallback: statsCallback,
		errorCallback: errorCallback,
		done:          make(chan bool),
	}

	if err := t.start(); err != nil {
		t.Stop()
		return nil, err
	}

	return t, nil
}

func (t *Tracer) Stop() {
	close(t.done)

	t.ioStartLink = gadgets.CloseLink(t.ioStartLink)
	t.startRequestLink = gadgets.CloseLink(t.startRequestLink)
	t.doneLink = gadgets.CloseLink(t.doneLink)

	t.objs.Close()
}

// readKernelSymbols reads /proc/kallsyms and returns a map of string (values
// are useless).
func readKernelSymbols() (map[string]int, error) {
	symbols := make(map[string]int)

	file, err := os.Open("/proc/kallsyms")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	// optionally, resize scanner's capacity for lines over 64K, see next example
	for scanner.Scan() {
		line := scanner.Text()

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		// The kernel function is the third field in /proc/kallsyms line:
		// 0000000000000000 t acpi_video_unregister_backlight      [video]
		// First is the symbol address and second is described in man nm.
		symbols[fields[2]] = 0
	}

	err = scanner.Err()
	if err != nil {
		return nil, err
	}

	return symbols, nil
}

// isKernelSymbol tests if given sym is within kernelSymbols.
func isKernelSymbol(sym string, kernelSymbols map[string]int) bool {
	_, ok := kernelSymbols[sym]
	return ok
}

func (t *Tracer) start() error {
	spec, err := loadBiotop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_set"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	kernelSymbols, err := readKernelSymbols()
	if err != nil {
		return fmt.Errorf("failed to load kernel symbols: %w", err)
	}

	// __blk_account_io_start and __blk_account_io_done were inlined in:
	// be6bfe36db17 ("block: inline hot paths of blk_account_io_*()").
	// which was included in kernel 5.16.
	// So let's be future proof and check if these symbols do not exist.
	blkAccountIoStartFunction := "__blk_account_io_start"
	if !isKernelSymbol(blkAccountIoStartFunction, kernelSymbols) {
		blkAccountIoStartFunction = "blk_account_io_start"
	}

	blkAccountIoDoneFunction := "__blk_account_io_done"
	if !isKernelSymbol(blkAccountIoDoneFunction, kernelSymbols) {
		blkAccountIoDoneFunction = "blk_account_io_done"
	}

	t.ioStartLink, err = link.Kprobe(blkAccountIoStartFunction, t.objs.BlkAccountIoStart, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.startRequestLink, err = link.Kprobe("blk_mq_start_request", t.objs.BlkMqStartRequest, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.doneLink, err = link.Kprobe(blkAccountIoDoneFunction, t.objs.BlkAccountIoDone, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.run()

	return nil
}

func (t *Tracer) nextStats() ([]types.Stats, error) {
	stats := []types.Stats{}

	var prev *C.struct_info_t = nil
	key := C.struct_info_t{}
	counts := t.objs.Counts

	defer func() {
		// delete elements
		err := counts.NextKey(nil, unsafe.Pointer(&key))
		if err != nil {
			return
		}

		for {
			if err := counts.Delete(key); err != nil {
				return
			}

			prev = &key
			if err := counts.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
				return
			}
		}
	}()

	// gather elements
	err := counts.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stats, nil
		}
		return nil, fmt.Errorf("error getting next key: %w", err)
	}

	for {
		val := C.struct_val_t{}
		if err := counts.Lookup(key, unsafe.Pointer(&val)); err != nil {
			return nil, err
		}

		stat := types.Stats{
			Write:      key.rwflag != 0,
			Major:      int(key.major),
			Minor:      int(key.minor),
			MountNsID:  uint64(key.mntnsid),
			Pid:        int32(key.pid),
			Comm:       C.GoString(&key.name[0]),
			Bytes:      uint64(val.bytes),
			MicroSecs:  uint64(val.us),
			Operations: uint32(val.io),
		}

		container := t.resolver.LookupContainerByMntns(stat.MountNsID)
		if container != nil {
			stat.Container = container.Name
			stat.Pod = container.Podname
			stat.Namespace = container.Namespace
			stat.Node = t.config.Node
		}

		stats = append(stats, stat)

		prev = &key
		if err := counts.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	types.SortStats(stats, t.config.SortBy)

	return stats, nil
}

func (t *Tracer) run() {
	ticker := time.NewTicker(t.config.Interval)

	go func() {
	loop:
		for {
			select {
			case <-t.done:
				break loop
			case <-ticker.C:
				stats, err := t.nextStats()
				if err != nil {
					t.errorCallback(err)
					return
				}

				n := len(stats)
				if n > t.config.MaxRows {
					n = t.config.MaxRows
				}
				t.statsCallback(stats[:n])
			}
		}
	}()
}
