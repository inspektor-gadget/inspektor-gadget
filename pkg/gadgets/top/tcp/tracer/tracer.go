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

//go:build !withoutebpf

package tracer

import (
	"context"
	"errors"
	"fmt"
	"syscall"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	log "github.com/sirupsen/logrus"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/top/tcp/types"
	eventtypes "github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -no-global-types -target $TARGET -type ip_key_t -type traffic_t -cc clang tcptop ./bpf/tcptop.bpf.c -- -I./bpf/ -I../../../../${TARGET}

type Config struct {
	MountnsMap   *ebpf.Map
	TargetPid    int32
	TargetFamily int32
	MaxRows      int
	Interval     time.Duration
	Iterations   int
	SortBy       []string
}

type Tracer struct {
	config             *Config
	objs               tcptopObjects
	tcpSendmsgLink     link.Link
	tcpCleanupRbufLink link.Link
	enricher           gadgets.DataEnricherByMntNs
	eventCallback      func(*top.Event[types.Stats])
	done               chan bool
	colMap             columns.ColumnMap[types.Stats]
}

func NewTracer(config *Config, enricher gadgets.DataEnricherByMntNs,
	eventCallback func(*top.Event[types.Stats]),
) (*Tracer, error) {
	t := &Tracer{
		config:        config,
		enricher:      enricher,
		eventCallback: eventCallback,
		done:          make(chan bool),
	}

	if err := t.install(); err != nil {
		t.close()
		return nil, err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		t.close()
		return nil, err
	}
	t.colMap = statCols.GetColumnMap()

	go t.run(context.TODO())

	return t, nil
}

// Stop stops the tracer
// TODO: Remove after refactoring
func (t *Tracer) Stop() {
	t.close()
}

func (t *Tracer) close() {
	close(t.done)

	t.tcpSendmsgLink = gadgets.CloseLink(t.tcpSendmsgLink)
	t.tcpCleanupRbufLink = gadgets.CloseLink(t.tcpCleanupRbufLink)

	t.objs.Close()
}

func (t *Tracer) install() error {
	spec, err := loadTcptop()
	if err != nil {
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	mapReplacements := map[string]*ebpf.Map{}
	filterByMntNs := false

	if t.config.MountnsMap != nil {
		filterByMntNs = true
		mapReplacements["mount_ns_filter"] = t.config.MountnsMap
	}

	consts := map[string]interface{}{
		"filter_by_mnt_ns": filterByMntNs,
		"target_pid":       t.config.TargetPid,
		"target_family":    t.config.TargetFamily,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("error RewriteConstants: %w", err)
	}

	opts := ebpf.CollectionOptions{
		MapReplacements: mapReplacements,
	}

	if err := spec.LoadAndAssign(&t.objs, &opts); err != nil {
		var ve *ebpf.VerifierError
		if errors.As(err, &ve) {
			log.Debugf("Verifier error: %+v\n", ve)
		}
		return fmt.Errorf("failed to load ebpf program: %w", err)
	}

	t.tcpSendmsgLink, err = link.Kprobe("tcp_sendmsg", t.objs.IgToptcpSdmsg, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	t.tcpCleanupRbufLink, err = link.Kprobe("tcp_cleanup_rbuf", t.objs.IgToptcpClean, nil)
	if err != nil {
		return fmt.Errorf("error opening kprobe: %w", err)
	}

	return nil
}

func (t *Tracer) nextStats() ([]*types.Stats, error) {
	stats := []*types.Stats{}

	var prev *tcptopIpKeyT = nil
	key := tcptopIpKeyT{}
	ips := t.objs.IpMap

	defer func() {
		// delete elements
		err := ips.NextKey(nil, unsafe.Pointer(&key))
		if err != nil {
			return
		}

		for {
			if err := ips.Delete(key); err != nil {
				return
			}

			prev = &key
			if err := ips.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
				return
			}
		}
	}()

	// gather elements
	err := ips.NextKey(nil, unsafe.Pointer(&key))
	if err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return stats, nil
		}
		return nil, fmt.Errorf("error getting next key: %w", err)
	}

	for {
		val := tcptopTrafficT{}
		if err := ips.Lookup(key, unsafe.Pointer(&val)); err != nil {
			return nil, err
		}

		stat := types.Stats{
			WithMountNsID: eventtypes.WithMountNsID{MountNsID: key.Mntnsid},
			Pid:           int32(key.Pid),
			Comm:          gadgets.FromCString(key.Name[:]),
			Sport:         key.Lport,
			Dport:         key.Dport,
			Family:        key.Family,
			Sent:          val.Sent,
			Received:      val.Received,
		}

		// eBPF program includes checks to only handle AF_INET and AF_INET6
		ipType := 4
		if key.Family == syscall.AF_INET6 {
			ipType = 6
		}

		stat.Saddr = gadgets.IPStringFromBytes(key.Saddr, ipType)
		stat.Daddr = gadgets.IPStringFromBytes(key.Daddr, ipType)

		if t.enricher != nil {
			t.enricher.EnrichByMntNs(&stat.CommonData, stat.MountNsID)
		}

		stats = append(stats, &stat)

		prev = &key
		if err := ips.NextKey(unsafe.Pointer(prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("error getting next key: %w", err)
		}
	}

	top.SortStats(stats, t.config.SortBy, &t.colMap)

	return stats, nil
}

func (t *Tracer) run(ctx context.Context) error {
	// Don't use a context with a timeout but a counter to avoid having to deal
	// with two timers: one for the timeout and another for the ticker.
	count := t.config.Iterations
	ticker := time.NewTicker(t.config.Interval)
	defer ticker.Stop()

	for {
		select {
		case <-t.done:
			// TODO: Once we completely move to use Run instead of NewTracer,
			// we can remove this as nobody will directly call Stop (cleanup).
			return nil
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			stats, err := t.nextStats()
			if err != nil {
				return fmt.Errorf("getting next stats: %w", err)
			}

			n := len(stats)
			if n > t.config.MaxRows {
				n = t.config.MaxRows
			}
			t.eventCallback(&top.Event[types.Stats]{Stats: stats[:n]})

			// Count down only if user requested a finite number of iterations
			// through a timeout.
			if t.config.Iterations > 0 {
				count--
				if count == 0 {
					return nil
				}
			}
		}
	}
}

func (t *Tracer) Run(gadgetCtx gadgets.GadgetContext) error {
	if err := t.init(gadgetCtx); err != nil {
		return fmt.Errorf("initializing tracer: %w", err)
	}

	defer t.close()
	if err := t.install(); err != nil {
		return fmt.Errorf("installing tracer: %w", err)
	}

	return t.run(gadgetCtx.Context())
}

func (t *Tracer) SetEventHandlerArray(handler any) {
	nh, ok := handler.(func(ev []*types.Stats))
	if !ok {
		panic("event handler invalid")
	}

	// TODO: add errorHandler
	t.eventCallback = func(ev *top.Event[types.Stats]) {
		if ev.Error != "" {
			return
		}
		nh(ev.Stats)
	}
}

func (t *Tracer) SetMountNsMap(mntnsMap *ebpf.Map) {
	t.config.MountnsMap = mntnsMap
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	tracer := &Tracer{
		config: &Config{
			TargetFamily: -1,
			TargetPid:    -1,
		},
		done: make(chan bool),
	}
	return tracer, nil
}

func (t *Tracer) init(gadgetCtx gadgets.GadgetContext) error {
	params := gadgetCtx.GadgetParams()
	t.config.MaxRows = params.Get(gadgets.ParamMaxRows).AsInt()
	t.config.SortBy = params.Get(gadgets.ParamSortBy).AsStringSlice()
	t.config.Interval = time.Second * time.Duration(params.Get(gadgets.ParamInterval).AsInt())
	t.config.TargetFamily, _ = types.ParseFilterByFamily(params.Get(types.FamilyParam).AsString())
	t.config.TargetPid = params.Get(types.PidParam).AsInt32()

	var err error
	if t.config.Iterations, err = top.ComputeIterations(t.config.Interval, gadgetCtx.Timeout()); err != nil {
		return err
	}

	statCols, err := columns.NewColumns[types.Stats]()
	if err != nil {
		return err
	}
	t.colMap = statCols.GetColumnMap()

	return nil
}
