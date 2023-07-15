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
	"time"

	"github.com/cilium/ebpf"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

// Delay between each garbage collection run.
const garbageCollectorInterval = 1 * time.Second

// Maximum size of a batch to lookup and delete.
// Setting this higher reduces the number of syscalls to GC a full map, but uses more memory.
const garbageCollectorBatchSize = 256

// startGarbageCollector runs a background goroutine to delete old query timestamps
// from the DNS query_map. This ensures that queries that never receive a response
// are deleted from the map.
//
// The garbage collector goroutine terminates when the context is done.
func startGarbageCollector(ctx context.Context, logger logger.Logger, gadgetParams *params.Params, queryMap *ebpf.Map) {
	if !gadgets.DetectBpfKtimeGetBootNs() {
		logger.Warnf("DNS latency will not be reported (requires Linux kernel 5.8 or later)")
		return
	}

	dnsTimeout := gadgetParams.Get(ParamDNSTimeout).AsDuration()

	logger.Debugf("starting garbage collection for DNS tracer with dnsTimeout %s", dnsTimeout)
	go func() {
		// Allocate the keys/values arrays once and reuse for each iteration.
		var (
			keysBatch   [garbageCollectorBatchSize]dnsQueryKeyT
			valuesBatch [garbageCollectorBatchSize]uint64
		)

		ticker := time.NewTicker(garbageCollectorInterval)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				logger.Debugf("stopping garbage collection for DNS tracer")
				return

			case <-ticker.C:
				logger.Debugf("executing DNS query map garbage collection")
				numDeleted, err := collectGarbage(dnsTimeout, queryMap, keysBatch[:], valuesBatch[:])
				if err != nil {
					logger.Errorf("collecting garbage: %w", err)
				} else if numDeleted > 0 {
					logger.Debugf("deleted %d entries from DNS query map", numDeleted)
				}
			}
		}
	}()
}

func collectGarbage(dnsTimeout time.Duration, queryMap *ebpf.Map, keysBatch []dnsQueryKeyT, valuesBatch []uint64) (int, error) {
	var (
		keysToDelete []dnsQueryKeyT
		prevKeyOut   interface{}
		nextKeyOut   dnsQueryKeyT
	)

	// Nil means start from the beginning.
	// Type of prevKeyOut is interface{}, not dnsQueryKeyT, to ensure that the first call
	// to BatchLookup sees an untyped nil (not an interface with value nil); otherwise it crashes.
	prevKeyOut = nil

	for {
		n, err := queryMap.BatchLookup(prevKeyOut, &nextKeyOut, keysBatch, valuesBatch, nil)
		if err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return 0, fmt.Errorf("looking up keys in query map: %w", err)
		}

		cutoffTs := types.Time(time.Now().Add(-1 * dnsTimeout).UnixNano())
		for i := 0; i < n; i++ {
			ts := gadgets.WallTimeFromBootTime(valuesBatch[i])
			if ts < cutoffTs {
				keysToDelete = append(keysToDelete, keysBatch[i])
			}
		}

		if errors.Is(err, ebpf.ErrKeyNotExist) {
			// This error means there are no more keys after the ones we just read.
			break
		}

		prevKeyOut = nextKeyOut
	}

	if len(keysToDelete) == 0 {
		return 0, nil
	}

	n, err := queryMap.BatchDelete(keysToDelete, nil)
	if err != nil {
		return 0, fmt.Errorf("deleting keys from query map: %w", err)
	}
	return n, nil
}
