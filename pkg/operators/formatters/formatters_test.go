package formatters

import (
	"fmt"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/stretchr/testify/require"
)

func TestGeneral(t *testing.T) {
	type testCaseDatum struct {
		value      any
		expected   any
		annotation map[string]string
	}

	type testCase struct {
		name             string
		kind             api.Kind
		epbftype         string
		putFunc          func(fa datasource.FieldAccessor, data datasource.Data, value any)
		getFormattedFunc func(fa datasource.FieldAccessor, data datasource.Data) (any, error)
		data             []testCaseDatum
	}

	testCases := []testCase{
		{
			name:     "timestamp",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.TimestampTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint64(data, value.(uint64))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			data: []testCaseDatum{
				{
					value:    uint64(60 * 60 * 1e9),
					expected: gadgets.WallTimeFromBootTime(60 * 60 * 1e9).String(),
					// annotation: map[string]string{"formatters.timestamp.format": "walltime"},
				},
			},
		},
		{
			name:     "signal",
			kind:     api.Kind_Uint32,
			epbftype: ebpftypes.SignalTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint32(data, value.(uint32))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			data: []testCaseDatum{
				{
					value:      uint32(9),
					expected:   "SIGKILL",
					annotation: nil,
				},
			},
		},
		{
			name:     "errno",
			kind:     api.Kind_Uint32,
			epbftype: ebpftypes.ErrnoTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint32(data, value.(uint32))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			data: []testCaseDatum{
				{
					value:      uint32(2),
					expected:   "ENOENT",
					annotation: nil,
				},
			},
		},
		{
			name:     "bytes",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.BytesTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint64(data, value.(uint64))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			data: []testCaseDatum{
				{
					value:      uint64(1048576),
					expected:   "1.0 MB",
					annotation: nil,
				},
			},
		},
		{
			name:     "duration",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.DurationTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint64(data, value.(uint64))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			data: []testCaseDatum{
				{
					value:      uint64(3*time.Second + 250*time.Millisecond),
					expected:   "3.25s",
					annotation: nil,
				},
			},
		},
		{
			name:     "syscall",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.SyscallTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint64(data, value.(uint64))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			data: []testCaseDatum{
				{
					value:      uint64(60),
					expected:   "SYS_EXIT",
					annotation: nil,
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, datum := range tc.data {
			t.Run(
				fmt.Sprintf("%s input: %v expected output: %v", tc.name, datum.value, datum.expected),
				func(t *testing.T) {
					var rpl replacer
					found := false
					for _, r := range replacers {
						if r.name == tc.name {
							rpl = r
							found = true
							break
						}
					}
					require.True(t, found, "replacer not found for "+tc.name)

					ds, err := datasource.New(datasource.TypeSingle, tc.name)
					require.NoError(t, err)

					fieldName := fmt.Sprintf("%s_raw", tc.name)
					fa, err := ds.AddField(fieldName, tc.kind, datasource.WithTags("type:"+tc.epbftype))
					require.NoError(t, err)

					if datum.annotation != nil {
						for k, v := range datum.annotation {
							fa.AddAnnotation(k, v)
						}
					}

					lg := logger.DefaultLogger()
					replacerFunc, err := rpl.replace(lg, ds, fa)
					require.NoError(t, err)

					data, err := ds.NewPacketSingle()
					require.NoError(t, err)

					tc.putFunc(fa, data, datum.value)

					err = replacerFunc(data)
					require.NoError(t, err)

					var formattedField datasource.FieldAccessor
					if datum.annotation != nil {
						for _, v := range datum.annotation {
							formattedField = ds.GetField(v)
						}
					} else {
						formattedField = ds.GetField(tc.name)
					}
					require.NotNil(t, formattedField, "formatted field not found for "+tc.name)
					res, err := tc.getFormattedFunc(formattedField, data)
					require.NoError(t, err)
					require.Equal(t, datum.expected, res)
				},
			)

		}
	}
}
func TestL3Formatter(t *testing.T) {
	type testDataL3 struct {
		rawIP      []byte
		expectedIP string
	}

	tests := []testDataL3{
		{
			rawIP:      []byte{192, 168, 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			expectedIP: "192.168.10.10",
		},
	}

	for _, td := range tests {
		t.Run(
			fmt.Sprintf("l3endpoint input: %v expected output: %v", td.rawIP, td.expectedIP),
			func(t *testing.T) {
				var rpl replacer
				found := false
				for _, r := range replacers {
					if r.name == "l3endpoint" {
						rpl = r
						found = true
						break
					}
				}
				require.True(t, found, "l3endpoint replacer not found")

				ds, err := datasource.New(datasource.TypeSingle, "l3endpoint")
				require.NoError(t, err)

				fa, err := ds.AddField("l3endpoint_raw", api.Kind_Bytes)
				require.NoError(t, err)

				ipField, err := fa.AddSubField("l3endpoint_raw", api.Kind_Bytes, datasource.WithTags("type:"+ebpftypes.IPAddrTypeName))
				require.NoError(t, err)

				versionField, err := fa.AddSubField("version", api.Kind_Uint8, datasource.WithTags("name:version"))
				require.NoError(t, err)

				lg := logger.DefaultLogger()
				replacerFunc, err := rpl.replace(lg, ds, fa)
				require.NoError(t, err)

				data, err := ds.NewPacketSingle()
				require.NoError(t, err)

				ipField.PutBytes(data, td.rawIP)
				versionField.PutUint8(data, 4)

				err = replacerFunc(data)
				require.NoError(t, err)

				formattedField := ds.GetField("l3endpoint_raw.l3endpoint")
				require.NotNil(t, formattedField)
				res, err := formattedField.String(data)
				require.NoError(t, err)
				require.Equal(t, td.expectedIP, res)
			},
		)
	}
}

func TestL4Formatter(t *testing.T) {
	type testDataL4 struct {
		rawIP            []byte
		port             uint16
		expectedEndpoint string
		protoNumber      *uint16
		expectedProto    *string
	}

	tests := []testDataL4{
		{
			rawIP:            []byte{192, 168, 10, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			port:             8080,
			expectedEndpoint: "192.168.10.10:8080",
			protoNumber:      uint16Ptr(6),
			expectedProto:    stringPtr("TCP"),
		},
		{
			rawIP:            []byte{10, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0},
			port:             80,
			expectedEndpoint: "10.0.0.1:80",
			protoNumber:      nil,
			expectedProto:    nil,
		},
	}

	for _, td := range tests {
		t.Run(
			fmt.Sprintf("l4endpoint raw: %v port: %d formatted: %v", td.rawIP, td.port, td.expectedEndpoint),
			func(t *testing.T) {

				var rpl replacer
				found := false
				for _, r := range replacers {
					if r.name == "l4endpoint" {
						rpl = r
						found = true
						break
					}
				}
				require.True(t, found, "l4endpoint replacer not found")

				ds, err := datasource.New(datasource.TypeSingle, "l4endpoint")
				require.NoError(t, err)

				fa, err := ds.AddField("l4endpoint_raw", api.Kind_Bytes)
				require.NoError(t, err)

				ipField, err := fa.AddSubField("l4endpoint_raw", api.Kind_Bytes, datasource.WithTags("type:"+ebpftypes.IPAddrTypeName))
				require.NoError(t, err)

				versionField, err := fa.AddSubField("version", api.Kind_Uint8, datasource.WithTags("name:version"))
				require.NoError(t, err)

				portField, err := fa.AddSubField("port", api.Kind_Uint16, datasource.WithTags("name:port"))
				require.NoError(t, err)

				var protoRawField datasource.FieldAccessor
				if td.protoNumber != nil {
					protoRawField, err = fa.AddSubField("proto_raw", api.Kind_Uint16, datasource.WithTags("name:proto_raw"))
					require.NoError(t, err)
				}

				lg := logger.DefaultLogger()
				replacerFunc, err := rpl.replace(lg, ds, fa)
				require.NoError(t, err)

				data, err := ds.NewPacketSingle()
				require.NoError(t, err)

				ipField.PutBytes(data, td.rawIP)
				versionField.PutUint8(data, 4)
				portField.PutUint16(data, td.port)
				if td.protoNumber != nil {
					protoRawField.PutUint16(data, *td.protoNumber)
				}

				err = replacerFunc(data)
				require.NoError(t, err)

				endpointField := ds.GetField("l4endpoint_raw.endpoint")
				require.NotNil(t, endpointField)
				endpointStr, err := endpointField.String(data)
				require.NoError(t, err)
				require.Equal(t, td.expectedEndpoint, endpointStr)

				if td.protoNumber != nil {
					protoField := ds.GetField("l4endpoint_raw.proto")
					require.NotNil(t, protoField)
					protoStr, err := protoField.String(data)
					require.NoError(t, err)
					require.Equal(t, *td.expectedProto, protoStr)
				}
			})
	}
}

func uint16Ptr(v uint16) *uint16 {
	return &v
}

func stringPtr(s string) *string {
	return &s
}
