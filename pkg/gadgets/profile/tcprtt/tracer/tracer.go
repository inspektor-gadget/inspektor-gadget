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
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/tcprtt/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target $TARGET -type hist -cc clang tcpRTT ./bpf/tcprtt.bpf.c -- -I./bpf/ -I../../../../${TARGET} -I ../../../common/

type Config struct {
	useMilliseconds     bool
	localAddrHist       bool
	remoteAddrHist      bool
	filterLocalAddress  uint32
	filterRemoteAddress uint32
}

type Tracer struct {
	objs                tcpRTTObjects
	tcpRcvEstKprobeLink link.Link

	config *Config
	logger logger.Logger
}

func (t *Tracer) RunWithResult(gadgetCtx gadgets.GadgetContext) ([]byte, error) {
	t.logger = gadgetCtx.Logger()

	if err := t.parseParams(gadgetCtx.GadgetParams()); err != nil {
		return nil, fmt.Errorf("parsing parameters: %w", err)
	}

	defer t.close()
	if err := t.install(); err != nil {
		return nil, fmt.Errorf("installing tracer: %w", err)
	}

	gadgetcontext.WaitForTimeoutOrDone(gadgetCtx)

	result, err := t.collectResult()
	if err != nil {
		return nil, fmt.Errorf("collecting result: %w", err)
	}
	return result, nil
}

func (t *Tracer) parseParams(params *params.Params) error {
	t.config.useMilliseconds = params.Get(ParamMilliseconds).AsBool()

	t.config.localAddrHist = params.Get(ParamByLocalAddress).AsBool()
	t.config.remoteAddrHist = params.Get(ParamByRemoteAddress).AsBool()
	if t.config.localAddrHist && t.config.remoteAddrHist {
		return fmt.Errorf("local and remote address histograms cannot be enabled at the same time")
	}

	lAddr := params.Get(ParamFilterLocalAddress).AsString()
	if lAddr != "" {
		l, err := gadgets.IPStringToUint32(lAddr)
		if err != nil {
			return fmt.Errorf("parsing local address: %w", err)
		}
		t.config.filterLocalAddress = l
	}

	rAddr := params.Get(ParamFilterRemoteAddress).AsString()
	if rAddr != "" {
		r, err := gadgets.IPStringToUint32(rAddr)
		if err != nil {
			return fmt.Errorf("parsing remote address: %w", err)
		}
		t.config.filterRemoteAddress = r
	}

	return nil
}

func (t *Tracer) collectResult() ([]byte, error) {
	histsMap := t.objs.Hists

	var key uint32
	if err := histsMap.NextKey(nil, unsafe.Pointer(&key)); err != nil {
		if errors.Is(err, ebpf.ErrKeyNotExist) {
			return nil, fmt.Errorf("no data was collected to generate the histogram")
		}
		return nil, fmt.Errorf("getting first histogram key: %w", err)
	}

	var unit histogram.Unit
	if t.config.useMilliseconds {
		unit = histogram.UnitMilliseconds
	} else {
		unit = histogram.UnitMicroseconds
	}

	var addressType types.AddressType
	if t.config.localAddrHist {
		addressType = types.AddressTypeLocal
	} else if t.config.remoteAddrHist {
		addressType = types.AddressTypeRemote
	} else {
		addressType = types.AddressTypeAll
	}

	report := types.Report{
		Histograms: make([]*types.ExtendedHistogram, 0),
	}

	var prev uint32
	for {
		var addr string
		if addressType == types.AddressTypeAll {
			addr = types.WildcardAddress
		} else {
			ptr := (*[4]byte)(unsafe.Pointer(&key))
			addr = netip.AddrFrom4(*ptr).String()
		}

		hist := tcpRTTHist{}
		if err := histsMap.Lookup(key, unsafe.Pointer(&hist)); err != nil {
			return nil, fmt.Errorf("getting data for histogram key %d (%s): %w", key, addr, err)
		}

		var avg float64
		if hist.Cnt > 0 {
			avg = float64(hist.Latency) / float64(hist.Cnt)
		}

		h := types.NewHistogram(unit, hist.Slots[:], addressType, addr, avg)
		report.Histograms = append(report.Histograms, h)

		prev = key
		if err := histsMap.NextKey(unsafe.Pointer(&prev), unsafe.Pointer(&key)); err != nil {
			if errors.Is(err, ebpf.ErrKeyNotExist) {
				break
			}
			return nil, fmt.Errorf("getting next histogram key: %w", err)
		}
	}

	return json.Marshal(report)
}

func (t *Tracer) close() {
	t.tcpRcvEstKprobeLink = gadgets.CloseLink(t.tcpRcvEstKprobeLink)

	t.objs.Close()
}

func (t *Tracer) install() error {
	var spec *ebpf.CollectionSpec

	spec, err := loadTcpRTT()
	if err != nil {
		return fmt.Errorf("loading specs: %w", err)
	}

	consts := map[string]interface{}{
		"targ_ms":         t.config.useMilliseconds,
		"targ_laddr_hist": t.config.localAddrHist,
		"targ_raddr_hist": t.config.remoteAddrHist,
		"targ_saddr":      t.config.filterLocalAddress,
		"targ_daddr":      t.config.filterRemoteAddress,
	}

	if err := spec.RewriteConstants(consts); err != nil {
		return fmt.Errorf("rewriting constants: %w", err)
	}

	if err := spec.LoadAndAssign(&t.objs, nil); err != nil {
		return fmt.Errorf("loading ebpf program: %w", err)
	}

	tcpRcvEstKprobeLink, err := link.Kprobe("tcp_rcv_established", t.objs.IgTcprcvestKp, nil)
	if err != nil {
		return fmt.Errorf("attaching kprobe: %w", err)
	}
	t.tcpRcvEstKprobeLink = tcpRcvEstKprobeLink

	return nil
}

func (g *GadgetDesc) NewInstance() (gadgets.Gadget, error) {
	return &Tracer{
		config: &Config{},
	}, nil
}
