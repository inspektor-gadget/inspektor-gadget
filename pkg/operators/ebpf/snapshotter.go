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
	"fmt"
	"io"
	"strings"

	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	containercollection "github.com/inspektor-gadget/inspektor-gadget/pkg/container-collection"
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
}

func (i *ebpfInstance) populateSnapshotter(t btf.Type, varName string) error {
	i.logger.Debugf("populating snapshotter %q", varName)

	parts := strings.Split(varName, typeSplitter)
	if len(parts) != 2 {
		return fmt.Errorf("invalid snapshotter info: %q", varName)
	}

	name := parts[0]
	structName := parts[1]

	i.logger.Debugf("> name       : %q", name)
	i.logger.Debugf("> struct name: %q", structName)

	snapConfig := i.config.Sub("snapshotters." + name)
	if snapConfig != nil {
		if configStructName := snapConfig.GetString("structName"); configStructName != "" && configStructName != structName {
			return fmt.Errorf("validating tracer %q: structName %q in eBPF program does not match %q from metadata file",
				name, configStructName, structName)
		}
		i.logger.Debugf("> successfully validated with metadata")
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
	}

	err := i.populateStructDirect(btfStruct)
	if err != nil {
		return fmt.Errorf("populating struct %q for snapshotter %q: %w", btfStruct.Name, name, err)
	}

	return nil
}

func (i *ebpfInstance) runSnapshotters() error {
	for _, l := range i.linksSnapshotters {
		i.logger.Debugf("starting snapshotter")
		switch l.typ {
		case "task":
			buf, err := bpfiterns.Read(l.link)
			if err != nil {
				return fmt.Errorf("reading iterator: %w", err)
			}
			// TODO: we need a link from iter to map
			for _, snapshotter := range i.snapshotters {
				// We'll for now use the first one that matches
				size := snapshotter.accessor.Size()
				if uint32(len(buf))%size == 0 {
					for i := uint32(0); i < uint32(len(buf)); i += size {
						data := snapshotter.ds.NewData()
						snapshotter.accessor.Set(data, buf[i:i+size])
						snapshotter.ds.EmitAndRelease(data)
					}
				}
			}
		case "tcp", "udp":
			namespacesToVisit := map[uint64]*containercollection.Container{}
			for _, c := range i.containers {
				namespacesToVisit[c.Netns] = c
			}
			for _, container := range namespacesToVisit {
				err := netnsenter.NetnsEnter(int(container.Pid), func() error {
					reader, err := l.link.Open()
					if err != nil {
						return err
					}
					defer reader.Close()
					buf, err := io.ReadAll(reader)
					if err != nil {
						return fmt.Errorf("reading iterator: %w", err)
					}
					// TODO: we need a link from iter to map
					for _, snapshotter := range i.snapshotters {
						// We'll for now use the first one that matches
						size := snapshotter.accessor.Size()
						if uint32(len(buf))%size == 0 {
							for i := uint32(0); i < uint32(len(buf)); i += size {
								data := snapshotter.ds.NewData()
								snapshotter.accessor.Set(data, buf[i:i+size])

								// TODO: this isn't ideal; make DS reserve memory / clean on demand
								// instead of allocating in here - or: reserve those 8 bytes in eBPF
								snapshotter.netns.Set(data, make([]byte, 8))
								snapshotter.netns.PutUint64(data, container.Netns)

								snapshotter.ds.EmitAndRelease(data)
							}
						}
					}
					return nil
				})
				if err != nil {
					return fmt.Errorf("iterating: %w", err)
				}
			}
		}
	}
	return nil
}
