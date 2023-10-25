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
	"runtime"
	"text/template"
	"time"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/btf"
	log "github.com/sirupsen/logrus"
	"go.opentelemetry.io/otel/metric"
	"golang.org/x/sys/unix"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/columns"
)

//go:embed templates/*.tpl
var tplFS embed.FS

var (
	metricsMapRegex = regexp.MustCompile("^metrics_map_([^_]+)$")
	metricsKeyRegex = regexp.MustCompile("^metrics_key_([^_]+)_(.*)$")
	metricsValRegex = regexp.MustCompile("^metrics_val_([^_]+)_(.*)$")
)

type MetricField struct {
	Name     string `yaml:"name"`
	CType    string `yaml:"ctype"`
	Array    bool   `yaml:"isArray"`
	ArrayLen int    `yaml:"arrayLen"`
}

type Metric struct {
	MetricName string        `yaml:"metricName"`
	Labels     []MetricField `yaml:"labels"`
	Values     []MetricField `yaml:"values"`
}

type Metrics []*Metric

func RenderMetricsHeader(m Metrics, out io.Writer) error {
	tmpl, err := template.New("metrics.h.tpl").ParseFS(tplFS, "templates/*.tpl")
	if err != nil {
		return fmt.Errorf("parsing templates: %w", err)
	}
	return tmpl.Execute(out, m)
}

type RuntimeMetricField struct {
	Name    string
	Type    reflect.Type
	Enabled bool
}

type RuntimeMetricMap struct {
	Keys []*RuntimeMetricField
}

type holder struct {
	Buf []byte
}

type RuntimeMetrics struct {
	Maps     map[string]*RuntimeMetricMap
	provider metric.MeterProvider
	cols     *columns.Columns[holder]
}

// TODO: move to lib
func getUnderlyingType(tf *btf.Typedef) (btf.Type, error) {
	switch typedMember := tf.Type.(type) {
	case *btf.Typedef:
		return getUnderlyingType(typedMember)
	default:
		return typedMember, nil
	}
}

func getSimpleType(typ btf.Type) reflect.Type {
	switch typedMember := typ.(type) {
	case *btf.Int:
		switch typedMember.Encoding {
		case btf.Signed:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(int8(0))
			case 2:
				return reflect.TypeOf(int16(0))
			case 4:
				return reflect.TypeOf(int32(0))
			case 8:
				return reflect.TypeOf(int64(0))
			}
		case btf.Unsigned:
			switch typedMember.Size {
			case 1:
				return reflect.TypeOf(uint8(0))
			case 2:
				return reflect.TypeOf(uint16(0))
			case 4:
				return reflect.TypeOf(uint32(0))
			case 8:
				return reflect.TypeOf(uint64(0))
			}
		case btf.Bool:
			return reflect.TypeOf(bool(false))
		case btf.Char:
			return reflect.TypeOf(uint8(0))
		}
	case *btf.Float:
		switch typedMember.Size {
		case 4:
			return reflect.TypeOf(float32(0))
		case 8:
			return reflect.TypeOf(float64(0))
		}
	case *btf.Typedef:
		typ, _ := getUnderlyingType(typedMember)
		return getSimpleType(typ)
	}

	return nil
}

func NewRuntimeMetrics(spec *ebpf.CollectionSpec) (*RuntimeMetrics, error) {
	rm := &RuntimeMetrics{
		Maps: make(map[string]*RuntimeMetricMap),
		cols: columns.MustCreateColumns[holder](),
	}

	for mapName, m := range spec.Maps {
		if !metricsMapRegex.MatchString(mapName) {
			log.Printf("skipping map %s", mapName)
			continue
		}
		log.Debugf("found metric map %s", mapName)

		// Read (possible) keys/labels
		keyStruct, ok := m.Key.(*btf.Struct)
		if !ok {
			log.Warnf("key of metric map %s not of type struct, skipping", mapName)
			continue
		}

		valStruct, ok := m.Value.(*btf.Struct)
		if !ok {
			log.Warnf("value of metric map %s not of type struct, skipping", mapName)
			continue
		}

		if keyStruct == nil || valStruct == nil {
		}

		rmm := &RuntimeMetricMap{}
		rm.Maps[mapName] = rmm

		for _, m := range keyStruct.Members {
			rmf := &RuntimeMetricField{
				Name: m.Name,
				Type: getSimpleType(m.Type),
			}

			if rmf.Type == nil {
				log.Warnf("skipping field %q; could not get base type", m.Name)
				continue
			}

			err := rm.cols.AddFields([]columns.DynamicField{
				{
					Attributes: &columns.Attributes{
						Name:    m.Name,
						RawName: m.Name,
					},
					Type:   rmf.Type,
					Offset: uintptr(m.Offset.Bytes()),
				},
			}, func(h *holder) unsafe.Pointer {
				return unsafe.Pointer(&h.Buf[0])
			})
			log.Printf("%q at offs %d", m.Name, m.Offset.Bytes())
			if err != nil {
				log.Warnf("could not add field for metric exporter: %v", err)
			}

			rmm.Keys = append(rmm.Keys, rmf)
		}
	}
	return rm, nil
}

func (r *RuntimeMetrics) Run(ctx context.Context, coll *ebpf.Collection, provider metric.MeterProvider) {
	r.provider = provider
	log.Printf("metrics running")
	ticker := time.NewTicker(time.Second)
	done := ctx.Done()
	for {
		select {
		case <-ticker.C:
			r.gatherMetrics(coll)
		case <-done:
			return
		}
	}
}

// BEGIN FIX UPSTREAM

const (
	BPF_MAP_LOOKUP_AND_DELETE_BATCH uintptr = 25
)

type Pointer struct {
	ptr unsafe.Pointer
}

type MapLookupBatchAttr struct {
	InBatch   Pointer
	OutBatch  Pointer
	Keys      Pointer
	Values    Pointer
	Count     uint32
	MapFd     uint32
	ElemFlags uint64
	Flags     uint64
}

func BPF(cmd uintptr, attr unsafe.Pointer, size uintptr) (uintptr, error) {
	for {
		r1, _, errNo := unix.Syscall(unix.SYS_BPF, uintptr(cmd), uintptr(attr), size)
		runtime.KeepAlive(attr)

		var err error
		if errNo != 0 {
			err = errNo
		}

		return r1, err
	}
}

// func (r *RuntimeMetrics) GetPrometheusConfig() *config.Config {
// 	return nil
// }
//
// func (r *RuntimeMetrics) SetMetricsProvider(provider metric.MeterProvider) {
// 	log.Printf("got metric provider")
// 	r.provider = provider
// }

func (r *RuntimeMetrics) gatherMetrics(coll *ebpf.Collection) {
	for mapName := range r.Maps {
		m, ok := coll.Maps[mapName]
		if !ok {
			log.Warnf("map not found: %s", m)
			continue
		}
		var prevKey []byte
		keySize := int(m.KeySize())
		valueSize := int(m.ValueSize())
		k := make([]byte, keySize*100)
		v := make([]byte, valueSize*100)

		kptr := Pointer{ptr: unsafe.Pointer(&k[0])}
		vptr := Pointer{ptr: unsafe.Pointer(&v[0])}
		for {
			nk := make([]byte, keySize)
			attr := MapLookupBatchAttr{
				MapFd:    uint32(m.FD()),
				Keys:     kptr,
				Values:   vptr,
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
				for _, c := range r.cols.GetOrderedColumns() {
					vv := columns.GetFieldAsString[holder](c)(&holder{Buf: ek})
					log.Printf("> %s: %s", c.Name, vv)
				}
				ev := v[i*valueSize : i*valueSize+valueSize]
				log.Printf("> %+v / %+v", ek, ev)
			}
			if errors.Is(err, unix.ENOENT) { // ebpf.ErrKeyNotExist
				break
			}
		}
	}
}
