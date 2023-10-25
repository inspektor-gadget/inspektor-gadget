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

package metrics

import (
	"context"
	"embed"
	_ "embed"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/types"
)

//go:embed templates/*.tpl
var tplFS embed.FS

var (
	metricsMapPrefix     = "metrics_map_"
	metricsMapRegex      = regexp.MustCompile("^metrics_map_([^_]+)$")
	metricsEnablerFormat = "metrics_key_%s_%s_enabled" // metricName, labelName
	mntNsIdType          = "mnt_ns_id_t"
	netNsIdType          = "net_ns_id_t"
)

type enrichType int

const (
	enrichTypeNone enrichType = iota
	enrichTypeMntNs
	enrichTypeNetNs
)

type MetricField struct {
	Name   string `yaml:"name"`
	CType  string `yaml:"cType"`
	Offset int    `yaml:"offset"`
}

type Metric struct {
	MetricName string        `yaml:"metricName"`
	Generate   bool          `yaml:"generate"`
	Labels     []MetricField `yaml:"labels"`
	Values     []MetricField `yaml:"values"`
}

type Metrics map[string]*Metric

func RenderMetricsHeader(m Metrics, out io.Writer) error {
	tmpl, err := template.New("metrics.h.tpl").ParseFS(tplFS, "templates/*.tpl")
	if err != nil {
		return fmt.Errorf("parsing templates: %w", err)
	}

	// Remove non-build maps
	buildMaps := make(Metrics)
	for k, v := range m {
		if v == nil || !v.Generate {
			continue
		}
		buildMaps[k] = v
	}

	return tmpl.Execute(out, buildMaps)
}

type RuntimeMetricField struct {
	MetricField

	// get/set at runtime
	disabled   bool
	rType      reflect.Type
	typeNames  []string
	column     *columns.Column[metricHolder]
	enrichType enrichType
}

func contains[T comparable](arr []T, val T) bool {
	for _, t := range arr {
		if t == val {
			return true
		}
	}
	return false
}

func (rmf *RuntimeMetricField) IsOfType(t string) bool {
	for _, tn := range rmf.typeNames {
		if tn == t {
			return true
		}
	}
	return false
}

type RuntimeMetricLabel struct {
	RuntimeMetricField
}

type RuntimeMetricValue struct {
	RuntimeMetricField
	ctr metric.Float64Counter
}

type RuntimeMetricMap struct {
	baseName   string // base name that the map has been created from
	exportName string // name to use for metrics export to Prometheus
	mapName    string // actual map name
	labels     []*RuntimeMetricField
	values     []*RuntimeMetricValue
	labelCols  *columns.Columns[metricHolder]
	valueCols  *columns.Columns[metricHolder]
	dynamic    bool
}

type metricHolder struct {
	buf []byte
}

type mntNsEnricher struct {
	mntnsid          uint64
	Node             string
	BasicK8sMetadata *types.BasicK8sMetadata
	BasicRuntimeData *types.BasicRuntimeMetadata
}

func (e *mntNsEnricher) GetMountNSID() uint64 {
	return e.mntnsid
}

func (e *mntNsEnricher) SetNode(node string) {
	e.Node = node
}

func (e *mntNsEnricher) SetPodMetadata(basicK8sMetadata *types.BasicK8sMetadata, basicRuntimeMetadata *types.BasicRuntimeMetadata) {
	e.BasicK8sMetadata = basicK8sMetadata
	e.BasicRuntimeData = basicRuntimeMetadata
}

func (e *mntNsEnricher) SetContainerMetadata(basicK8sMetadata *types.BasicK8sMetadata, basicRuntimeMetadata *types.BasicRuntimeMetadata) {
	e.BasicK8sMetadata = basicK8sMetadata
	e.BasicRuntimeData = basicRuntimeMetadata
}

type RuntimeMetrics struct {
	Maps      map[string]*RuntimeMetricMap
	provider  metric.MeterProvider
	gadgetCtx gadgets.GadgetContext
	operator  operators.OperatorInstance
}

// NewRuntimeMetrics creates a new runtime for metric collection; the spec is used to add maps automatically that
// have been created using our helpers (by a specific naming convention); configMetrics are passed from the gadget's
// metadata to create manually added maps
// TODO: validation should be added to check that configMetrics matches their spec counterparts
func NewRuntimeMetrics(spec *ebpf.CollectionSpec, configMetrics Metrics) (*RuntimeMetrics, error) {
	rm := &RuntimeMetrics{
		Maps: make(map[string]*RuntimeMetricMap),
	}

	collectMaps := make(map[string]struct{})

	for mapName := range configMetrics {
		collectMaps[mapName] = struct{}{}
	}

	for mapName, m := range spec.Maps {
		matches := metricsMapRegex.MatchString(mapName)
		if _, ok := collectMaps[mapName]; !ok && !matches {
			continue
		}
		log.Debugf("found metric map %s", mapName)

		// Read (possible) keys/labels
		labelStruct, ok := m.Key.(*btf.Struct)
		if !ok {
			log.Warnf("key of metric map %s not of type struct, skipping", mapName)
			continue
		}

		valStruct, ok := m.Value.(*btf.Struct)
		if !ok {
			log.Warnf("value of metric map %s not of type struct, skipping", mapName)
			continue
		}

		rmm := &RuntimeMetricMap{
			labelCols:  columns.MustCreateColumns[metricHolder](),
			valueCols:  columns.MustCreateColumns[metricHolder](),
			dynamic:    matches,
			mapName:    mapName,
			baseName:   strings.TrimPrefix(mapName, metricsMapPrefix),
			exportName: strings.TrimPrefix(mapName, metricsMapPrefix),
		}

		if rmm.dynamic {
			delete(collectMaps, rmm.baseName)
		} else {
			delete(collectMaps, mapName)
		}

		labelLookup := make(map[string]*RuntimeMetricField)
		for _, m := range labelStruct.Members {
			// we cannot allow duplicate label names
			if _, ok := labelLookup[m.Name]; ok {
				return nil, fmt.Errorf("duplicate label %q", m.Name)
			}

			t, typeNames := getType(m.Type)
			rmf := &RuntimeMetricField{
				MetricField: MetricField{
					Name: m.Name,
				},
				rType:     t,
				typeNames: typeNames,
			}

			// Temporary workaround for enrichments
			if contains(typeNames, mntNsIdType) {
				rmf.enrichType = enrichTypeMntNs
			} else if contains(typeNames, netNsIdType) {
				rmf.enrichType = enrichTypeNetNs
			}

			if rmf.rType == nil {
				log.Warnf("skipping field %q; could not get base type", m.Name)
				continue
			}

			err := rmm.labelCols.AddFields([]columns.DynamicField{
				{
					Attributes: &columns.Attributes{
						Name:    m.Name,
						RawName: m.Name,
					},
					Type:   rmf.rType,
					Offset: uintptr(m.Offset.Bytes()),
				},
			}, func(h *metricHolder) unsafe.Pointer {
				return unsafe.Pointer(&h.buf[0])
			})
			if err != nil {
				log.Warnf("could not add field for metric exporter: %v", err)
				continue
			}

			rmf.column, _ = rmm.labelCols.GetColumn(m.Name) // TOD
			rmm.labels = append(rmm.labels, rmf)

			labelLookup[rmf.Name] = rmf
		}

		valueLookup := make(map[string]*RuntimeMetricValue)
		for _, m := range valStruct.Members {
			// we also don't allow duplicate value names
			if _, ok := valueLookup[m.Name]; ok {
				return nil, fmt.Errorf("duplicate label %q", m.Name)
			}

			t, typeNames := getType(m.Type)
			rmf := &RuntimeMetricValue{
				RuntimeMetricField: RuntimeMetricField{
					MetricField: MetricField{
						Name: m.Name,
					},
					rType:     t,
					typeNames: typeNames,
				},
			}

			err := rmm.valueCols.AddFields([]columns.DynamicField{
				{
					Attributes: &columns.Attributes{
						Name:    m.Name,
						RawName: m.Name,
					},
					Type:   rmf.rType,
					Offset: uintptr(m.Offset.Bytes()),
				},
			}, func(h *metricHolder) unsafe.Pointer {
				return unsafe.Pointer(&h.buf[0])
			})
			if err != nil {
				log.Warnf("could not add field for metric exporter: %v", err)
				continue
			}

			rmf.column, _ = rmm.valueCols.GetColumn(m.Name) // TODO
			rmm.values = append(rmm.values, rmf)

			valueLookup[rmf.Name] = rmf
		}

		// if we're dynamic, we need to make sure we have necessary variables to enable/disable labels
		if rmm.dynamic {
			// tmpLabelLookup := maps.Clone(labelLookup) // needs go 1.21
			tmpLabelLookup := make(map[string]*RuntimeMetricField)
			for k, v := range labelLookup {
				tmpLabelLookup[fmt.Sprintf(metricsEnablerFormat, rmm.baseName, k)] = v
			}
			it := spec.Types.Iterate()
			for it.Next() {
				v, ok := it.Type.(*btf.Var)
				if !ok {
					continue
				}
				delete(tmpLabelLookup, v.Name)
			}

			if len(tmpLabelLookup) > 0 {
				k := make([]string, 0)
				for name := range tmpLabelLookup {
					k = append(k, name)
				}
				return nil, fmt.Errorf("missing enabler variables for dynamic map: %v", strings.Join(k, ", "))
			}
		}

		rm.Maps[mapName] = rmm
	}

	for mapName := range collectMaps {
		log.Warnf("map name %q declared in metadata, but not found", mapName)
	}

	return rm, nil
}

func (r *RuntimeMetrics) Run(
	gadgetCtx gadgets.GadgetContext,
	coll *ebpf.Collection,
	provider metric.MeterProvider,
	operatorInstances operators.OperatorInstances,
) {
	r.provider = provider
	r.gadgetCtx = gadgetCtx

	// Register metrics
	for _, mi := range r.Maps {
		mtr := r.provider.Meter(mi.exportName)
		for _, v := range mi.values {
			ctr, err := mtr.Float64Counter(v.Name)
			if err != nil {
				log.Printf("could not add value field %q: %v", v.Name, err)
				continue
			}
			v.ctr = ctr
		}
	}

	// Find operator for enrichment; this is a temporary solution
	// TODO
	for _, op := range operatorInstances {
		if op.Name() == "LocalManagerTrace" || op.Name() == "KubeManagerInstance" {
			// TODO: make sure the gadget actually instantiates the required operator
			r.operator = op
		}
	}

	log.Printf("metrics running")
	ticker := time.NewTicker(time.Second)
	done := gadgetCtx.Context().Done()
	for {
		select {
		case <-ticker.C:
			r.gatherMetrics(coll)
		case <-done:
			return
		}
	}
}

// gatherMetrics will go through all available metrics and collect them from the eBPF maps; it will automatically
// delete them while doing so, to keep memory footprint in eBPF low
func (r *RuntimeMetrics) gatherMetrics(coll *ebpf.Collection) {
	for mapName, mi := range r.Maps {
		m, ok := coll.Maps[mapName]
		if !ok {
			log.Warnf("map not found: %s", m)
			continue
		}

		// pointer to previous key (initialize as empty)
		var prevKey []byte

		// TODO: cache these buffers
		keySize := int(m.KeySize())
		valueSize := int(m.ValueSize())
		k := make([]byte, keySize*100)
		v := make([]byte, valueSize*100)

		labelsPtr := Pointer{ptr: unsafe.Pointer(&k[0])}
		valuesPtr := Pointer{ptr: unsafe.Pointer(&v[0])}
		for {
			// TODO: use cilium lib once raw byte access has been added
			// TODO: open PR to actually make that happen
			nk := make([]byte, keySize)
			attr := MapLookupBatchAttr{
				MapFd:    uint32(m.FD()),
				Keys:     labelsPtr,
				Values:   valuesPtr,
				Count:    uint32(100),
				OutBatch: Pointer{ptr: unsafe.Pointer(&nk[0])},
			}
			if prevKey != nil {
				attr.InBatch = Pointer{ptr: unsafe.Pointer(&prevKey[0])}
			}

			_, err := BPF(BPF_MAP_LOOKUP_AND_DELETE_BATCH, unsafe.Pointer(&attr), unsafe.Sizeof(attr))
			if err != nil && !errors.Is(err, unix.ENOENT) {
				log.Warnf("err: %v", err)
				break
			}
			n := int(attr.Count)

			prevKey = nk
			for i := 0; i < n; i++ {
				ek := k[i*keySize : i*keySize+keySize]

				// build attrs from labels
				attrs := make([]attribute.KeyValue, 0)
				for _, c := range mi.labels {
					vv := columns.GetFieldAsString[metricHolder](c.column)(&metricHolder{buf: ek}) // TODO: optimize

					if c.enrichType == enrichTypeMntNs {
						// TODO: make sure type is correct!
						enr := &mntNsEnricher{
							mntnsid: columns.GetFieldAsNumberFunc[uint64, metricHolder](c.column)(&metricHolder{buf: ek}),
						}

						r.operator.EnrichEvent(enr)

						// TODO: make sure these are actually requested
						if enr.BasicK8sMetadata != nil {
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("k8s.namespace"),
								Value: attribute.StringValue(enr.BasicK8sMetadata.Namespace),
							})
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("k8s.podname"),
								Value: attribute.StringValue(enr.BasicK8sMetadata.PodName),
							})
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("k8s.containername"),
								Value: attribute.StringValue(enr.BasicK8sMetadata.ContainerName),
							})
						}
						if enr.BasicRuntimeData != nil {
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("runtime"),
								Value: attribute.StringValue(enr.BasicRuntimeData.RuntimeName.String()),
							})
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("containerid"),
								Value: attribute.StringValue(enr.BasicRuntimeData.ContainerID),
							})
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("containername"),
								Value: attribute.StringValue(enr.BasicRuntimeData.ContainerName),
							})
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("containerimagename"),
								Value: attribute.StringValue(enr.BasicRuntimeData.ContainerImageName),
							})
							attrs = append(attrs, attribute.KeyValue{
								Key:   attribute.Key("containerimagedigest"),
								Value: attribute.StringValue(enr.BasicRuntimeData.ContainerImageDigest),
							})
						}
						continue
					}

					attrs = append(attrs, attribute.KeyValue{
						Key:   attribute.Key(c.Name),
						Value: attribute.StringValue(vv),
					})
				}

				ev := v[i*valueSize : i*valueSize+valueSize]
				// now add values
				for _, c := range mi.values {
					// vv := columns.GetFieldAsNumberFunc[float64, metricHolder](c.column)(&metricHolder{buf: ek}) // TODO: optimize; needs Kind to be set
					vv := columns.GetFieldAsString[metricHolder](c.column)(&metricHolder{buf: ev}) // TODO: optimize
					f, _ := strconv.ParseFloat(vv, 64)
					c.ctr.Add(context.Background(), f, metric.WithAttributes(attrs...))
				}
			}
			if errors.Is(err, unix.ENOENT) { // ebpf.ErrKeyNotExist when doing this with cilium/ebpf later on
				break
			}
		}
	}
}
