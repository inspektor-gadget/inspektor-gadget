// Copyright 2024 The Inspektor Gadget authors
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

package ebpfoperator

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/netnsenter"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
)

type linkSnapshotter struct {
	link *link.Iter
	typ  string
}

type Snapshotter struct {
	metadatav1.Snapshotter

	ds       datasource.DataSource
	accessor datasource.FieldAccessor
	netns    datasource.FieldAccessor

	// iterators is a list of iterators that this snapshotter needs to run to
	// get the data. This information is gathered from the snapshotter
	// definition in the eBPF program.
	iterators map[string]struct{}

	// links is a map of iterators to their links. Links are created when the
	// iterator is attached to the kernel.
	links map[string]*linkSnapshotter
}

func (i *ebpfInstance) parseSnapshotterPrograms(programs []string) (map[string]struct{}, error) {
	iterators := make(map[string]struct{}, len(programs))

	for _, program := range programs {
		if program == "" {
			return nil, errors.New("empty program name")
		}

		i.logger.Debugf("> program %q", program)

		// Check if the program is in the eBPF object
		p, ok := i.collectionSpec.Programs[program]
		if !ok {
			return nil, fmt.Errorf("program %q not found in eBPF object", program)
		}

		if p.Type != ebpf.Tracing || !strings.HasPrefix(p.SectionName, "iter/") {
			return nil, fmt.Errorf("invalid program %q: expecting type %q and section name prefix \"iter/\", got %q and %q",
				program, ebpf.Tracing, p.Type, p.SectionName)
		}

		iterators[program] = struct{}{}
	}

	return iterators, nil
}

func (i *ebpfInstance) populateSnapshotter(t btf.Type, varName string) error {
	i.logger.Debugf("populating snapshotter %q", varName)

	parts := strings.Split(varName, typeSplitter)
	if len(parts) < 3 {
		// At least one program is required
		return fmt.Errorf("invalid snapshotter definition, expected format: <name>___<structName>___<program1>___...___<programN>, got %q",
			varName)
	}

	name := parts[0]
	structName := parts[1]

	i.logger.Debugf("> name       : %q", name)
	i.logger.Debugf("> struct name: %q", structName)

	snapConfig := i.config.Sub("snapshotters." + name)
	if snapConfig != nil {
		if configStructName := snapConfig.GetString("structName"); configStructName != "" && configStructName != structName {
			return fmt.Errorf("validating snapshotter %q: structName %q in eBPF program does not match %q from metadata file",
				name, configStructName, structName)
		}
		i.logger.Debugf("> successfully validated with metadata")
	}

	iterators, err := i.parseSnapshotterPrograms(parts[2:])
	if err != nil {
		return fmt.Errorf("parsing snapshotter %q programs: %w", name, err)
	}

	if _, ok := i.snapshotters[name]; ok {
		i.logger.Debugf("snapshotter %q already defined, skipping", name)
		return nil
	}

	var btfStruct *btf.Struct
	if err := i.collectionSpec.Types.TypeByName(structName, &btfStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", structName, err)
	}

	i.logger.Debugf("adding snapshotter %q", name)
	i.snapshotters[name] = &Snapshotter{
		Snapshotter: metadatav1.Snapshotter{
			StructName: btfStruct.Name,
		},
		iterators: iterators,
		links:     make(map[string]*linkSnapshotter),
	}

	err = i.populateStructDirect(btfStruct)
	if err != nil {
		return fmt.Errorf("populating struct %q for snapshotter %q: %w", btfStruct.Name, name, err)
	}

	return nil
}

func (i *ebpfInstance) runSnapshotters() error {
	for sName, snapshotter := range i.snapshotters {
		i.logger.Debugf("Running snapshotter %q", sName)

		for pName, l := range snapshotter.links {
			i.logger.Debugf("Running iterator %q", pName)
			switch l.typ {
			case "task":
				buf, err := bpfiterns.Read(l.link)
				if err != nil {
					return fmt.Errorf("reading iterator %q: %w", pName, err)
				}

				size := snapshotter.accessor.Size()
				if uint32(len(buf))%size != 0 {
					return fmt.Errorf("iter %q returned an invalid buffer's size %d, expected multiple of %d",
						pName, len(buf), size)
				}

				for i := uint32(0); i < uint32(len(buf)); i += size {
					data := snapshotter.ds.NewData()
					snapshotter.accessor.Set(data, buf[i:i+size])
					snapshotter.ds.EmitAndRelease(data)
				}
			case "tcp", "udp":
				visitedNetNs := make(map[uint64]struct{})
				for _, container := range i.containers {
					_, visited := visitedNetNs[container.Netns]
					if visited {
						continue
					}
					visitedNetNs[container.Netns] = struct{}{}

					err := netnsenter.NetnsEnter(int(container.Pid), func() error {
						reader, err := l.link.Open()
						if err != nil {
							return err
						}
						defer reader.Close()

						buf, err := io.ReadAll(reader)
						if err != nil {
							return fmt.Errorf("reading iterator %q: %w", pName, err)
						}

						size := snapshotter.accessor.Size()
						if uint32(len(buf))%size != 0 {
							return fmt.Errorf("iter %q returned an invalid buffer's size %d, expected multiple of %d",
								pName, len(buf), size)
						}

						for i := uint32(0); i < uint32(len(buf)); i += size {
							data := snapshotter.ds.NewData()
							snapshotter.accessor.Set(data, buf[i:i+size])
							snapshotter.netns.PutUint64(data, container.Netns)

							snapshotter.ds.EmitAndRelease(data)
						}

						return nil
					})
					if err != nil {
						return fmt.Errorf("entering container %q's netns to run iterator %q: %w",
							container.Runtime.RuntimeName, pName, err)
					}
				}
			}
		}
	}
	return nil
}
