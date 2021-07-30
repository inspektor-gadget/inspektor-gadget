// Copyright 2019-2021 The Inspektor Gadget authors
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

package tracer

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"

	"github.com/kinvolk/inspektor-gadget/pkg/gadgets"
)

const (
	BPF_ITER_NAME = "dump_task"
)

func RunCollector(mntnsmap string) (string, error) {
	var prog []byte
	if mntnsmap == "" {
		prog = ebpfProg
	} else {
		if filepath.Dir(mntnsmap) != gadgets.PIN_PATH {
			return "", fmt.Errorf("error while checking pin path: only paths in %s are supported", gadgets.PIN_PATH)
		}

		prog = ebpfProgWithFilter
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		return "", fmt.Errorf("failed to load asset: %w", err)
	}

	spec.Maps["containers"].Pinning = ebpf.PinByName
	if mntnsmap != "" {
		spec.Maps["filter"].Name = filepath.Base(mntnsmap)
		spec.Maps["filter"].Pinning = ebpf.PinByName
	}

	coll, err := ebpf.NewCollectionWithOptions(spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: gadgets.PIN_PATH,
			},
		},
	)
	if err != nil {
		return "", fmt.Errorf("failed to create BPF collection: %w", err)
	}

	dumpTask, ok := coll.Programs[BPF_ITER_NAME]
	if !ok {
		return "", fmt.Errorf("failed to find BPF iterator %q", BPF_ITER_NAME)
	}
	dumpTaskIter, err := link.AttachIter(link.IterOptions{
		Program: dumpTask,
	})
	if err != nil {
		return "", fmt.Errorf("failed to attach BPF iterator: %w", err)
	}

	file, err := dumpTaskIter.Open()
	if err != nil {
		return "", fmt.Errorf("failed to open BPF iterator: %w", err)
	}
	defer file.Close()

	contents, err := ioutil.ReadAll(file)
	if err != nil {
		return "", fmt.Errorf("failed to read BPF iterator: %w", err)
	}
	return string(contents), nil
}
