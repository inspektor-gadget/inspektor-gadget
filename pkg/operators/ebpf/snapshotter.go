// Copyright 2024-2025 The Inspektor Gadget authors
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
	"os"
	"strings"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	"github.com/cilium/ebpf/link"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	bpfiterns "github.com/inspektor-gadget/inspektor-gadget/pkg/utils/bpf-iter-ns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/utils/nsenter"
)

type linkIterator struct {
	link *link.Iter
	typ  string
}

type Iterator struct {
	structName string

	ds       datasource.DataSource
	accessor datasource.FieldAccessor

	// iterators is a list of iterator programs that this Iterator needs to run to
	// get the data. This information is gathered from the iterator
	// definition in the eBPF program.
	iterators map[string]struct{}

	// links is a map of iterator programs to their links. Links are created when the
	// iterator is attached to the kernel.
	links map[string]*linkIterator

	interval time.Duration
	count    int

	fetchOnStop bool
}

func (i *ebpfInstance) parseIteratorPrograms(programs []string) (map[string]struct{}, error) {
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

func (i *ebpfInstance) populateIterators(t btf.Type, varName string) error {
	i.logger.Debugf("populating iterator %q", varName)

	parts := strings.Split(varName, typeSplitter)
	if len(parts) < 3 {
		// At least one program is required
		return fmt.Errorf("invalid iterator definition, expected format: <name>___<structName>___<program1>___...___<programN>, got %q",
			varName)
	}

	name := parts[0]
	structName := parts[1]

	i.logger.Debugf("> name       : %q", name)
	i.logger.Debugf("> struct name: %q", structName)

	iterators, err := i.parseIteratorPrograms(parts[2:])
	if err != nil {
		return fmt.Errorf("parsing iterator %q programs: %w", name, err)
	}

	if _, ok := i.iterators[name]; ok {
		i.logger.Debugf("iterator %q already defined, skipping", name)
		return nil
	}

	var btfStruct *btf.Struct
	if err := i.collectionSpec.Types.TypeByName(structName, &btfStruct); err != nil {
		return fmt.Errorf("finding struct %q in eBPF object: %w", structName, err)
	}

	i.logger.Debugf("adding iterator %q", name)
	i.iterators[name] = &Iterator{
		structName: btfStruct.Name,
		iterators:  iterators,
		links:      make(map[string]*linkIterator),
	}

	err = i.populateStructDirect(btfStruct)
	if err != nil {
		return fmt.Errorf("populating struct %q for iterator %q: %w", btfStruct.Name, name, err)
	}

	return nil
}

func (i *ebpfInstance) runIterators() error {
	for sName, iter := range i.iterators {
		fetch := func() error {
			i.logger.Debugf("Running iterator %q", sName)

			pArray, err := iter.ds.NewPacketArray()
			if err != nil {
				return fmt.Errorf("creating new packet: %w", err)
			}

			for pName, l := range iter.links {
				i.logger.Debugf("Running iterator program %q", pName)

				if !isIteratorKindSupported(l.typ) {
					return fmt.Errorf("iterator kind %q is not supported", l.typ)
				}
				if !isIteratorKindPerNetNs(l.typ) {
					buf, err := bpfiterns.Read(l.link)
					if err != nil {
						return fmt.Errorf("reading iterator %q: %w", pName, err)
					}

					size := iter.accessor.Size()
					if uint32(len(buf))%size != 0 {
						return fmt.Errorf("iter %q returned an invalid buffer's size %d, expected multiple of %d",
							pName, len(buf), size)
					}

					for i := uint32(0); i < uint32(len(buf)); i += size {
						data := pArray.New()
						if err := iter.accessor.Set(data, buf[i:i+size]); err != nil {
							pArray.Release(data)
							return fmt.Errorf("setting data element %d: %w", i, err)
						}
						pArray.Append(data)
					}
				} else {
					visitedNetNs := make(map[uint64]struct{})
					for _, container := range i.containers {
						_, visited := visitedNetNs[container.Netns]
						if visited {
							continue
						}
						visitedNetNs[container.Netns] = struct{}{}

						err := nsenter.NetnsEnter(int(container.ContainerPid()), func() error {
							reader, err := l.link.Open()
							if err != nil {
								return err
							}
							defer reader.Close()

							buf, err := io.ReadAll(reader)
							if err != nil {
								return fmt.Errorf("reading iterator %q: %w", pName, err)
							}

							size := iter.accessor.Size()
							if uint32(len(buf))%size != 0 {
								return fmt.Errorf("iter %q returned an invalid buffer's size %d, expected multiple of %d",
									pName, len(buf), size)
							}

							for i := uint32(0); i < uint32(len(buf)); i += size {
								data := pArray.New()
								if err := iter.accessor.Set(data, buf[i:i+size]); err != nil {
									pArray.Release(data)
									return fmt.Errorf("setting data element %d: %w", i, err)
								}
								pArray.Append(data)
							}

							return nil
						})
						if err != nil && !errors.Is(err, os.ErrNotExist) {
							return fmt.Errorf("entering container %q's netns to run iterator %q: %w",
								container.Runtime.ContainerName, pName, err)
						}
					}
				}
			}

			if err := iter.ds.EmitAndRelease(pArray); err != nil {
				return fmt.Errorf("emitting iter %q data: %w", sName, err)
			}
			return nil
		}
		i.wg.Add(1)
		go func() {
			defer i.wg.Done()
			if iter.interval == 0 && iter.count == 1 {
				// Only a single time if interval is zero and count is 1
				err := fetch()
				if err != nil {
					i.logger.Warnf("error running iterator %q: %v", sName, err)
				}
				return
			}
			ctr := 0
			tickerChan := make(<-chan time.Time)
			if iter.interval > 0 {
				tickerChan = time.NewTicker(iter.interval).C
			}
			for {
				select {
				case <-i.done:
					if iter.fetchOnStop {
						i.logger.Debugf("fetching on stop")
						err := fetch()
						if err != nil {
							i.logger.Warnf("error running iterator %q: %v", sName, err)
						}
					}
					return
				case <-tickerChan:
					err := fetch()
					if err != nil {
						i.logger.Warnf("error running iterator %q: %v", sName, err)
					}
					ctr++
					if iter.count > 0 && ctr >= iter.count {
						// TODO: close DS
						return
					}
				}
			}
		}()
	}
	return nil
}

// isIteratorKindPerNetNs returns true if the iterator kind needs to be run per
// network namespace.
func isIteratorKindPerNetNs(kind string) bool {
	if kind == "tcp" || kind == "udp" {
		return true
	}
	return false
}

// isIteratorKindSupported returns true if the iterator kind is supported by
// Inspektor Gadget.
func isIteratorKindSupported(kind string) bool {
	// Linux 6.9 supports the following iterator kinds:
	//
	// $ git grep -w '^DEFINE_BPF_ITER_FUNC'|sed 's/^.*(\([a-z0-9_]*\),.*$/\1/'
	// bpf_link bpf_map bpf_map_elem bpf_prog bpf_sk_storage_map cgroup
	// ipv6_route ksym netlink sockmap task task_file task_vma tcp udp unix
	//
	// But at the moment, only a subset is supported by Inspektor Gadget.
	switch kind {
	case "task", "task_file", "ksym", "tcp", "udp":
		return true
	}
	return false
}
