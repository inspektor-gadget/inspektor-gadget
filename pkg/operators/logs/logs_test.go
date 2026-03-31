// Copyright 2026 The Inspektor Gadget authors
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

package logs

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	logrus "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"gopkg.in/natefinch/lumberjack.v2"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/testing/gadget-context"
)

// testGadgetContext wraps MockGadgetContext and adds control over IsRemoteCall and ID.
type testGadgetContext struct {
	*gadgetcontext.MockGadgetContext
	remoteCall bool
	id         string
}

func (t *testGadgetContext) IsRemoteCall() bool {
	return t.remoteCall
}

func (t *testGadgetContext) ID() string {
	return t.id
}

// newTestOperator creates a logsOperator with the given config and a buffer as output.
func newTestOperator(format string, buf *bytes.Buffer) *logsOperator {
	return &logsOperator{
		enabled: true,
		channel: ChannelStderr,
		format:  format,
		mode:    ModeAll,
		writer:  buf,
	}
}

func TestJSON_BasicOutput(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	fooField, err := ds.AddField("foo", api.Kind_String)
	require.NoError(t, err)

	barField, err := ds.AddField("bar", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "trace_open",
		instanceID: "abc123",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	err = inst.PreStart(gadgetCtx)
	require.NoError(t, err)

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	require.NoError(t, fooField.PutString(packet, "hello"))
	require.NoError(t, barField.PutInt32(packet, 42))

	require.NoError(t, ds.EmitAndRelease(packet))

	// Parse the NDJSON output
	line := strings.TrimSpace(buf.String())
	require.NotEmpty(t, line)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &envelope))

	assert.Equal(t, EventTypeString, envelope["type"])
	assert.Equal(t, float64(0), envelope["seq"])
	assert.Equal(t, "trace_open", envelope["gadget"])
	assert.Equal(t, "test-ds", envelope["datasource"])
	assert.Equal(t, "abc123", envelope["instanceID"])
	assert.Contains(t, envelope, "timestamp")

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok, "data field should be an object")
	assert.Equal(t, "hello", data["foo"])
	assert.Equal(t, float64(42), data["bar"])
}

func TestJSON_NoInstanceID(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	_, err = ds.AddField("val", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "trace_open",
		instanceID: "", // no instance ID (live session)
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, ds.EmitAndRelease(packet))

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &envelope))

	// instanceID should be absent when empty
	_, hasInstanceID := envelope["instanceID"]
	assert.False(t, hasInstanceID, "instanceID should be omitted for live sessions")
}

func TestJSON_ControlCharacters(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	field, err := ds.AddField("msg", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	require.NoError(t, field.PutString(packet, "line1\nline2\ttab\x00null"))
	require.NoError(t, ds.EmitAndRelease(packet))

	line := strings.TrimSpace(buf.String())

	// The output must be valid JSON (control chars escaped)
	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &envelope), "output should be valid JSON")

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "line1\nline2\ttab\x00null", data["msg"])
}

func TestLogfmt_BasicOutput(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	fooField, err := ds.AddField("foo", api.Kind_String)
	require.NoError(t, err)

	barField, err := ds.AddField("bar", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatLogfmt, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "trace_open",
		instanceID: "abc123",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	require.NoError(t, fooField.PutString(packet, "hello"))
	require.NoError(t, barField.PutInt32(packet, 42))

	require.NoError(t, ds.EmitAndRelease(packet))

	line := strings.TrimSpace(buf.String())
	assert.Contains(t, line, "type=gadget-data")
	assert.Contains(t, line, "seq=0")
	assert.Contains(t, line, "gadget=trace_open")
	assert.Contains(t, line, "datasource=test-ds")
	assert.Contains(t, line, "instanceID=abc123")
	assert.Contains(t, line, "timestamp=")
	assert.Contains(t, line, "bar=42")
	assert.Contains(t, line, "foo=hello")
}

func TestLogfmt_QuotedValues(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	field, err := ds.AddField("msg", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatLogfmt, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	require.NoError(t, field.PutString(packet, `hello world "quoted" a=b`))
	require.NoError(t, ds.EmitAndRelease(packet))

	line := strings.TrimSpace(buf.String())
	// Value should be quoted because it contains spaces, = and "
	assert.Contains(t, line, `msg="hello world \"quoted\" a=b"`)
}

func TestLogfmt_EmptyValue(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	field, err := ds.AddField("msg", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatLogfmt, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	require.NoError(t, field.PutString(packet, ""))
	require.NoError(t, ds.EmitAndRelease(packet))

	line := strings.TrimSpace(buf.String())
	// Empty values should be quoted
	assert.Contains(t, line, `msg=""`)
}

func TestDisabled(t *testing.T) {
	op := &logsOperator{enabled: false}

	gadgetCtx := &testGadgetContext{
		MockGadgetContext: &gadgetcontext.MockGadgetContext{
			Ctx: context.Background(),
		},
		remoteCall: true,
		id:         "abc123",
	}

	inst, err := op.InstantiateDataOperator(gadgetCtx, nil)
	require.NoError(t, err)
	assert.Nil(t, inst, "disabled operator should return nil instance")
}

func TestNotRemoteCall(t *testing.T) {
	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	gadgetCtx := &testGadgetContext{
		MockGadgetContext: &gadgetcontext.MockGadgetContext{
			Ctx: context.Background(),
		},
		remoteCall: false,
		id:         "",
	}

	inst, err := op.InstantiateDataOperator(gadgetCtx, nil)
	require.NoError(t, err)
	assert.Nil(t, inst, "non-remote call should return nil instance")
}

func TestDetachedMode_SkipsLiveSession(t *testing.T) {
	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)
	op.mode = ModeDetached

	gadgetCtx := &testGadgetContext{
		MockGadgetContext: &gadgetcontext.MockGadgetContext{
			Ctx: context.Background(),
		},
		remoteCall: true,
		id:         "", // live session: no ID
	}

	inst, err := op.InstantiateDataOperator(gadgetCtx, nil)
	require.NoError(t, err)
	assert.Nil(t, inst, "detached mode should skip live sessions")
}

func TestDetachedMode_AllowsDetachedInstance(t *testing.T) {
	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)
	op.mode = ModeDetached

	gadgetCtx := &testGadgetContext{
		MockGadgetContext: &gadgetcontext.MockGadgetContext{
			Ctx: context.Background(),
		},
		remoteCall: true,
		id:         "abc123", // detached: has ID
	}

	inst, err := op.InstantiateDataOperator(gadgetCtx, nil)
	require.NoError(t, err)
	assert.NotNil(t, inst, "detached mode should allow instances with ID")
}

func TestJSON_NestedFields(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	parent, err := ds.AddField("proc", api.Kind_Invalid, datasource.WithFlags(datasource.FieldFlagContainer|datasource.FieldFlagEmpty))
	require.NoError(t, err)

	_, err = parent.AddSubField("comm", api.Kind_String)
	require.NoError(t, err)
	_, err = parent.AddSubField("pid", api.Kind_Int32)
	require.NoError(t, err)

	_, err = ds.AddField("other", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	commAcc := ds.GetField("proc.comm")
	require.NotNil(t, commAcc)
	pidAcc := ds.GetField("proc.pid")
	require.NotNil(t, pidAcc)
	otherAcc := ds.GetField("other")
	require.NotNil(t, otherAcc)

	require.NoError(t, commAcc.PutString(packet, "sh"))
	require.NoError(t, pidAcc.PutInt32(packet, 1234))
	require.NoError(t, otherAcc.PutString(packet, "hello"))

	require.NoError(t, ds.EmitAndRelease(packet))

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(strings.TrimSpace(buf.String())), &envelope))

	data, ok := envelope["data"].(map[string]any)
	require.True(t, ok)

	// The JSON formatter renders nested fields as a nested object
	proc, ok := data["proc"].(map[string]any)
	require.True(t, ok, "proc should be a nested object")
	assert.Equal(t, "sh", proc["comm"])
	assert.Equal(t, float64(1234), proc["pid"])
	assert.Equal(t, "hello", data["other"])
}

func TestJSON_MultipleEvents(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	field, err := ds.AddField("val", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	// Emit 3 events
	for i := int32(0); i < 3; i++ {
		packet, err := ds.NewPacketSingle()
		require.NoError(t, err)
		require.NoError(t, field.PutInt32(packet, i))
		require.NoError(t, ds.EmitAndRelease(packet))
	}

	// Each line should be valid NDJSON
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 3)

	for i, line := range lines {
		var envelope map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &envelope), "line %d should be valid JSON", i)
		data := envelope["data"].(map[string]any)
		assert.Equal(t, float64(i), data["val"])
	}
}

func TestJSON_FileChannel(t *testing.T) {
	tmpDir := t.TempDir()
	logFile := filepath.Join(tmpDir, "gadget.log")

	lj := &lumberjack.Logger{
		Filename:   logFile,
		MaxSize:    1, // 1MB
		MaxBackups: 1,
	}
	defer lj.Close()

	op := &logsOperator{
		enabled: true,
		channel: ChannelFile,
		format:  FormatJSON,
		mode:    ModeAll,
		writer:  lj,
		closer:  lj,
	}

	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	field, err := ds.AddField("msg", api.Kind_String)
	require.NoError(t, err)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "file-test",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, field.PutString(packet, "file-output"))
	require.NoError(t, ds.EmitAndRelease(packet))

	// Read the file and verify
	data, err := os.ReadFile(logFile)
	require.NoError(t, err)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal(bytes.TrimSpace(data), &envelope))

	assert.Equal(t, EventTypeString, envelope["type"])
	assert.Equal(t, "file-test", envelope["instanceID"])

	d, ok := envelope["data"].(map[string]any)
	require.True(t, ok)
	assert.Equal(t, "file-output", d["msg"])
}

func TestLogfmt_NestedFields(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	parent, err := ds.AddField("proc", api.Kind_Invalid, datasource.WithFlags(datasource.FieldFlagContainer|datasource.FieldFlagEmpty))
	require.NoError(t, err)

	_, err = parent.AddSubField("comm", api.Kind_String)
	require.NoError(t, err)
	_, err = parent.AddSubField("pid", api.Kind_Int32)
	require.NoError(t, err)

	_, err = ds.AddField("other", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatLogfmt, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)

	commAcc := ds.GetField("proc.comm")
	require.NotNil(t, commAcc)
	pidAcc := ds.GetField("proc.pid")
	require.NotNil(t, pidAcc)
	otherAcc := ds.GetField("other")
	require.NotNil(t, otherAcc)

	require.NoError(t, commAcc.PutString(packet, "sh"))
	require.NoError(t, pidAcc.PutInt32(packet, 1234))
	require.NoError(t, otherAcc.PutString(packet, "hello"))

	require.NoError(t, ds.EmitAndRelease(packet))

	line := strings.TrimSpace(buf.String())

	// Container/parent fields should be skipped; only leaf fields appear
	assert.Contains(t, line, "proc.comm=sh")
	assert.Contains(t, line, "proc.pid=1234")
	assert.Contains(t, line, "other=hello")
	assert.NotContains(t, line, "proc=")
}

func TestMultipleDataSources(t *testing.T) {
	ds1, err := datasource.New(datasource.TypeSingle, "ds-alpha")
	require.NoError(t, err)
	field1, err := ds1.AddField("a", api.Kind_String)
	require.NoError(t, err)

	ds2, err := datasource.New(datasource.TypeSingle, "ds-beta")
	require.NoError(t, err)
	field2, err := ds2.AddField("b", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "multi-test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"ds-alpha": ds1,
			"ds-beta":  ds2,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	// Emit from ds1
	pkt1, err := ds1.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, field1.PutString(pkt1, "hello"))
	require.NoError(t, ds1.EmitAndRelease(pkt1))

	// Emit from ds2
	pkt2, err := ds2.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, field2.PutInt32(pkt2, 99))
	require.NoError(t, ds2.EmitAndRelease(pkt2))

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)

	// Parse both lines and check datasource names
	dsNames := make(map[string]bool)
	for _, line := range lines {
		var envelope map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &envelope))
		dsNames[envelope["datasource"].(string)] = true
	}
	assert.True(t, dsNames["ds-alpha"], "should contain ds-alpha events")
	assert.True(t, dsNames["ds-beta"], "should contain ds-beta events")
}

func TestJSON_TypeArray(t *testing.T) {
	ds, err := datasource.New(datasource.TypeArray, "snapshot-ds")
	require.NoError(t, err)

	nameField, err := ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	pidField, err := ds.AddField("pid", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "snapshot_process",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"snapshot-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)

	elem1 := pArray.New()
	require.NoError(t, nameField.PutString(elem1, "nginx"))
	require.NoError(t, pidField.PutInt32(elem1, 100))
	pArray.Append(elem1)

	elem2 := pArray.New()
	require.NoError(t, nameField.PutString(elem2, "bash"))
	require.NoError(t, pidField.PutInt32(elem2, 200))
	pArray.Append(elem2)

	require.NoError(t, ds.EmitAndRelease(pArray))

	// Should produce a single log line with "data" as a JSON array
	line := strings.TrimSpace(buf.String())
	require.NotEmpty(t, line)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &envelope))

	assert.Equal(t, EventTypeString, envelope["type"])
	assert.Equal(t, float64(0), envelope["seq"])
	assert.Equal(t, "snapshot_process", envelope["gadget"])
	assert.Equal(t, "snapshot-ds", envelope["datasource"])

	dataArr, ok := envelope["data"].([]any)
	require.True(t, ok, "data field should be an array")
	require.Len(t, dataArr, 2)

	first := dataArr[0].(map[string]any)
	assert.Equal(t, "nginx", first["name"])

	second := dataArr[1].(map[string]any)
	assert.Equal(t, "bash", second["name"])
}

func TestJSON_TypeArray_Elements(t *testing.T) {
	ds, err := datasource.New(datasource.TypeArray, "snapshot-ds")
	require.NoError(t, err)

	nameField, err := ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	// Set the annotation to fan out elements
	ds.AddAnnotation(AnnotationArrayHandling, ArrayHandlingElements)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "snapshot_process",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"snapshot-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)

	elem1 := pArray.New()
	require.NoError(t, nameField.PutString(elem1, "nginx"))
	pArray.Append(elem1)

	elem2 := pArray.New()
	require.NoError(t, nameField.PutString(elem2, "bash"))
	pArray.Append(elem2)

	require.NoError(t, ds.EmitAndRelease(pArray))

	// Should produce two lines, each with "data" as an object, sharing the same seq
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)

	var env1, env2 map[string]any
	require.NoError(t, json.Unmarshal([]byte(lines[0]), &env1))
	require.NoError(t, json.Unmarshal([]byte(lines[1]), &env2))

	// Both lines share the same seq
	assert.Equal(t, env1["seq"], env2["seq"])
	assert.Equal(t, float64(0), env1["seq"])

	// Each line has "data" as an object (not array)
	data1, ok := env1["data"].(map[string]any)
	require.True(t, ok, "data should be an object")
	assert.Equal(t, "nginx", data1["name"])

	data2, ok := env2["data"].(map[string]any)
	require.True(t, ok, "data should be an object")
	assert.Equal(t, "bash", data2["name"])
}

func TestLogfmt_TypeArray(t *testing.T) {
	ds, err := datasource.New(datasource.TypeArray, "snapshot-ds")
	require.NoError(t, err)

	nameField, err := ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatLogfmt, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "snapshot_process",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"snapshot-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)

	elem1 := pArray.New()
	require.NoError(t, nameField.PutString(elem1, "nginx"))
	pArray.Append(elem1)

	elem2 := pArray.New()
	require.NoError(t, nameField.PutString(elem2, "bash"))
	pArray.Append(elem2)

	require.NoError(t, ds.EmitAndRelease(pArray))

	// Two lines with same seq
	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 2)

	assert.Contains(t, lines[0], "seq=0")
	assert.Contains(t, lines[1], "seq=0")
	assert.Contains(t, lines[0], "name=nginx")
	assert.Contains(t, lines[1], "name=bash")
}

func TestSeq_Increments(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	_, err = ds.AddField("val", api.Kind_Int32)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	for i := 0; i < 3; i++ {
		packet, err := ds.NewPacketSingle()
		require.NoError(t, err)
		require.NoError(t, ds.EmitAndRelease(packet))
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	require.Len(t, lines, 3)

	for i, line := range lines {
		var envelope map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &envelope))
		assert.Equal(t, float64(i), envelope["seq"], "seq should increment")
	}
}

func TestJSON_TypeArray_Empty(t *testing.T) {
	ds, err := datasource.New(datasource.TypeArray, "snapshot-ds")
	require.NoError(t, err)

	_, err = ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "snapshot_process",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"snapshot-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	// Emit an empty array
	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)
	require.NoError(t, ds.EmitAndRelease(pArray))

	line := strings.TrimSpace(buf.String())
	require.NotEmpty(t, line, "empty array should still produce a line")

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &envelope))

	assert.Equal(t, EventTypeEmptyString, envelope["type"])
	assert.Equal(t, float64(0), envelope["seq"])
	assert.Equal(t, "snapshot_process", envelope["gadget"])
	assert.Nil(t, envelope["data"], "empty envelope should have no data field")
}

func TestJSON_TypeArray_Elements_Empty(t *testing.T) {
	ds, err := datasource.New(datasource.TypeArray, "snapshot-ds")
	require.NoError(t, err)

	_, err = ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	ds.AddAnnotation(AnnotationArrayHandling, ArrayHandlingElements)

	var buf bytes.Buffer
	op := newTestOperator(FormatJSON, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "snapshot_process",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"snapshot-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)
	require.NoError(t, ds.EmitAndRelease(pArray))

	line := strings.TrimSpace(buf.String())
	require.NotEmpty(t, line)

	var envelope map[string]any
	require.NoError(t, json.Unmarshal([]byte(line), &envelope))

	assert.Equal(t, EventTypeEmptyString, envelope["type"])
	assert.Equal(t, float64(0), envelope["seq"])
	assert.Nil(t, envelope["data"])
}

func TestLogfmt_TypeArray_Empty(t *testing.T) {
	ds, err := datasource.New(datasource.TypeArray, "snapshot-ds")
	require.NoError(t, err)

	_, err = ds.AddField("name", api.Kind_String)
	require.NoError(t, err)

	var buf bytes.Buffer
	op := newTestOperator(FormatLogfmt, &buf)

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "snapshot_process",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"snapshot-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	pArray, err := ds.NewPacketArray()
	require.NoError(t, err)
	require.NoError(t, ds.EmitAndRelease(pArray))

	line := strings.TrimSpace(buf.String())
	require.NotEmpty(t, line, "empty array should still produce a line")

	assert.Contains(t, line, "type=gadget-data-empty")
	assert.Contains(t, line, "seq=0")
	assert.NotContains(t, line, "name=", "empty envelope should have no data fields")
}

func TestNegativeMaxSizeMB(t *testing.T) {
	op := &logsOperator{channel: ChannelFile, format: FormatJSON, mode: ModeAll, filename: "/tmp/test.log", maxSizeMB: -1}
	err := op.setup()
	assert.ErrorContains(t, err, "max-size-mb must be >= 0")
}

// mockRotator records Rotate() calls for testing.
type mockRotator struct {
	mu        sync.Mutex
	rotated   int
	rotateErr error
}

func (m *mockRotator) Rotate() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.rotated++
	return m.rotateErr
}

func (m *mockRotator) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.rotated
}

func TestSIGHUP_TriggersRotation(t *testing.T) {
	mr := &mockRotator{}
	op := &logsOperator{
		enabled: true,
		channel: ChannelFile,
		format:  FormatJSON,
		mode:    ModeAll,
		writer:  &bytes.Buffer{},
		rotator: mr,
	}

	op.startSignalHandler()
	defer op.Close()

	// Send a signal directly on the channel to simulate SIGHUP
	op.sigChan <- syscall.SIGHUP

	assert.Eventually(t, func() bool {
		return mr.count() == 1
	}, time.Second, 10*time.Millisecond, "Rotate should have been called once")
}

// errorWriter is an io.Writer that always returns an error.
type errorWriter struct {
	err error
}

func (e *errorWriter) Write(p []byte) (int, error) {
	return 0, e.err
}

func TestWriteError_IsLogged(t *testing.T) {
	ds, err := datasource.New(datasource.TypeSingle, "test-ds")
	require.NoError(t, err)

	_, err = ds.AddField("msg", api.Kind_String)
	require.NoError(t, err)

	writeErr := errors.New("disk full")
	op := &logsOperator{
		enabled: true,
		channel: ChannelStderr,
		format:  FormatJSON,
		mode:    ModeAll,
		writer:  &errorWriter{err: writeErr},
	}

	inst := &logsOperatorInstance{
		op:         op,
		gadgetName: "test",
		instanceID: "",
	}

	gadgetCtx := &gadgetcontext.MockGadgetContext{
		Ctx: context.Background(),
		DataSources: map[string]datasource.DataSource{
			"test-ds": ds,
		},
	}

	require.NoError(t, inst.PreStart(gadgetCtx))

	// Capture logrus output to verify the error is logged.
	var logBuffer bytes.Buffer
	origOut := logrus.StandardLogger().Out
	logrus.SetOutput(&logBuffer)
	defer logrus.SetOutput(origOut)

	// Emit a packet — the write will fail but should not panic
	packet, err := ds.NewPacketSingle()
	require.NoError(t, err)
	require.NoError(t, ds.EmitAndRelease(packet))

	// Verify the write error was logged
	logContent := logBuffer.String()
	assert.Contains(t, logContent, "write error")
	assert.Contains(t, logContent, "disk full")
}

func TestClose_StopsSignalHandler(t *testing.T) {
	mr := &mockRotator{}
	op := &logsOperator{
		enabled: true,
		channel: ChannelFile,
		format:  FormatJSON,
		mode:    ModeAll,
		writer:  &bytes.Buffer{},
		rotator: mr,
	}

	op.startSignalHandler()
	require.NotNil(t, op.sigChan)
	require.NotNil(t, op.sigStop)
	require.NotNil(t, op.sigDone)

	err := op.Close()
	require.NoError(t, err)

	assert.Nil(t, op.sigChan, "sigChan should be nil after Close")
	assert.Nil(t, op.sigStop, "sigStop should be nil after Close")
	assert.Nil(t, op.sigDone, "sigDone should be nil after Close")
}

func TestInvalidChannel(t *testing.T) {
	op := &logsOperator{channel: "invalid", format: FormatJSON, mode: ModeAll}
	err := op.setup()
	assert.ErrorContains(t, err, "unsupported logs channel")
}

func TestInvalidFormat(t *testing.T) {
	op := &logsOperator{channel: ChannelStderr, format: "xml", mode: ModeAll}
	err := op.setup()
	assert.ErrorContains(t, err, "unsupported logs format")
}

func TestInvalidMode(t *testing.T) {
	op := &logsOperator{channel: ChannelStderr, format: FormatJSON, mode: "invalid"}
	err := op.setup()
	assert.ErrorContains(t, err, "unsupported logs mode")
}

func TestFileChannel_MissingFilename(t *testing.T) {
	op := &logsOperator{channel: ChannelFile, format: FormatJSON, mode: ModeAll}
	err := op.setup()
	assert.ErrorContains(t, err, "operator.logs.filename must be set")
}

func TestFileChannel_DefaultMaxSize(t *testing.T) {
	tmpDir := t.TempDir()

	op := &logsOperator{
		channel:  ChannelFile,
		format:   FormatJSON,
		mode:     ModeAll,
		filename: filepath.Join(tmpDir, "gadget.log"),
	}
	require.NoError(t, op.setup())
	defer op.Close()

	// maxSizeMB=0 should fall back to DefaultMaxSizeMB
	lj, ok := op.writer.(*lumberjack.Logger)
	require.True(t, ok)
	assert.Equal(t, DefaultMaxSizeMB, lj.MaxSize)
}
