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

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"path/filepath"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

const (
	PIN_PATH      = "/sys/fs/bpf/gadget"
	BPF_ITER_NAME = "dump_task"
)

var flagFilter string

func init() {
	flag.StringVar(&flagFilter, "mntnsmap", "", "list tasks running in mount namespaces in this BPF map only")
}

func increaseRlimit() error {
	limit := &unix.Rlimit{
		Cur: unix.RLIM_INFINITY,
		Max: unix.RLIM_INFINITY,
	}
	return unix.Setrlimit(unix.RLIMIT_MEMLOCK, limit)
}

func main() {
	flag.Parse()
	if err := increaseRlimit(); err != nil {
		log.Fatalf("Failed to increase memlock limit: %s", err)
	}

	var prog []byte
	if flagFilter == "" {
		prog = ebpfProg
	} else {
		if filepath.Dir(flagFilter) != PIN_PATH {
			log.Fatalf("Error while checking pin path: only paths in %s are supported", PIN_PATH)
		}

		prog = ebpfProgWithFilter
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(prog))
	if err != nil {
		log.Fatalf("Failed to load asset: %s", err)
	}

	spec.Maps["containers"].Pinning = ebpf.PinByName
	if flagFilter != "" {
		spec.Maps["filter"].Name = filepath.Base(flagFilter)
		spec.Maps["filter"].Pinning = ebpf.PinByName
	}

	coll, err := ebpf.NewCollectionWithOptions(spec,
		ebpf.CollectionOptions{
			Maps: ebpf.MapOptions{
				PinPath: PIN_PATH,
			},
		},
	)
	if err != nil {
		log.Fatalf("Failed to create BPF collection: %s", err)
	}

	dumpTask, ok := coll.Programs[BPF_ITER_NAME]
	if !ok {
		log.Fatalf("Failed to find BPF iterator %q", BPF_ITER_NAME)
	}
	dumpTaskIter, err := link.AttachIter(link.IterOptions{
		Program: dumpTask,
	})
	if err != nil {
		log.Fatalf("Failed to attach BPF iterator: %s", err)
	}

	file, err := dumpTaskIter.Open()
	if err != nil {
		log.Fatalf("Failed to open BPF iterator: %s", err)
	}
	defer file.Close()

	contents, err := ioutil.ReadAll(file)
	if err != nil {
		log.Fatalf("Failed to read BPF iterator: %s", err)
	}
	fmt.Printf("%s", string(contents))
}
