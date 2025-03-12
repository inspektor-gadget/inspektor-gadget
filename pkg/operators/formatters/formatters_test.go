package formatters

import (
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
	"github.com/stretchr/testify/require"
)

type testCase struct {
	name             string
	kind             api.Kind
	epbftype         string
	putFunc          func(fa datasource.FieldAccessor, data datasource.Data)
	getFormattedFunc func(fa datasource.FieldAccessor, data datasource.Data) (any, error)
	expected         any
}

func TestGeneral(t *testing.T) {

	testCases := []testCase{
		{
			name:     "timestamp",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.TimestampTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data) {
				fa.PutUint64(data, uint64(60*60*1e9))
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			expected: gadgets.WallTimeFromBootTime(60 * 60 * 1e9).String(),
		},
		{
			name:     "signal",
			kind:     api.Kind_Uint32, // Signal number is stored as uint32
			epbftype: ebpftypes.SignalTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data) {
				fa.PutUint32(data, uint32(9)) // SIGKILL
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			expected: "SIGKILL",
		},
		{
			name:     "errno",
			kind:     api.Kind_Uint32, // Errno is stored as uint32
			epbftype: ebpftypes.ErrnoTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data) {
				fa.PutUint32(data, uint32(2)) // ENOENT (No such file or directory)
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			expected: "ENOENT",
		},
		{
			name:     "bytes",
			kind:     api.Kind_Uint64, // Bytes are stored as uint64
			epbftype: ebpftypes.BytesTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data) {
				fa.PutUint64(data, uint64(1048576)) // 1 MiB in bytes
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			expected: "1.0 MB", // Expected human-readable output
		},
		{
			name:     "duration",
			kind:     api.Kind_Uint64, // Duration is stored as uint64 nanoseconds
			epbftype: ebpftypes.DurationTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data) {
				fa.PutUint64(data, uint64(3*time.Second+250*time.Millisecond)) // 3.25 seconds
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			expected: "3.25s", // Expected formatted duration
		},
		{
			name:     "syscall",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.SyscallTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data) {
				fa.PutUint64(data, uint64(60)) // 60 corresponds to SYS_exit in Linux
			},
			getFormattedFunc: func(fa datasource.FieldAccessor, data datasource.Data) (any, error) {
				return fa.String(data)
			},
			expected: "SYS_EXIT", // Expected formatted syscall name
		},
	}

	for _, tc := range testCases {
		var rpl replacer
		found := false
		for _, r := range replacers {
			if r.name == tc.name {
				found = true
				rpl = r
				break
			}
		}
		require.True(t, found)

		ds, _ := datasource.New(datasource.TypeSingle, tc.name)
		fa, _ := ds.AddField(fmt.Sprintf("%s_raw", tc.name), tc.kind, datasource.WithTags("type:"+tc.epbftype))
		lg := logger.DefaultLogger()

		replacerFunc, _ := rpl.replace(lg, ds, fa) // adds a new formatted field to the datasource
		data, _ := ds.NewPacketSingle()
		tc.putFunc(fa, data)

		_ = replacerFunc(data)
		fa = ds.GetField(tc.name)
		res, _ := tc.getFormattedFunc(fa, data)

		require.Equal(t, tc.expected, res)
	}
}

type testCaseIp struct {
	name     string
	kind     api.Kind
	epbftype string
	putFunc  func(ipField datasource.FieldAccessor, versionField datasource.FieldAccessor, data datasource.Data)
	expected any
}

func TestIpFormatter(t *testing.T) {

	testCases := []testCaseIp{
		{
			name:     "l3endpoint",
			kind:     api.Kind_Bytes,
			epbftype: ebpftypes.IPAddrTypeName,
			putFunc: func(ipField datasource.FieldAccessor, versionField datasource.FieldAccessor, data datasource.Data) {

				bytes := make([]byte, 16)
				ipBytes := net.IPv4(192, 168, 1, 1).To16()
				copy(bytes, ipBytes)
				ipField.PutBytes(data, bytes)
				fmt.Printf("confirming ipField: %v %v\n", ipField.Get(data), ipField.Size())

				versionField.PutUint8(data, 4) // IPv4 = 4, IPv6 = 6

				fmt.Printf("confirming versionField: %v\n", versionField.Get(data))
			},
			expected: "192.168.10.10",
		},
	}

	for _, tc := range testCases {
		var rpl replacer
		found := false
		for _, r := range replacers {
			if r.name == tc.name {
				found = true
				rpl = r
				break
			}
		}
		require.True(t, found)

		ds, _ := datasource.New(datasource.TypeSingle, tc.name)
		fa, _ := ds.AddField(fmt.Sprintf("%s_raw", tc.name), tc.kind)

		// Add the raw IP address field as a 16-byte field (expected format)
		ipField, _ := fa.AddSubField("l3endpoint_raw", api.Kind_Bytes, datasource.WithTags("type:"+ebpftypes.IPAddrTypeName, "size:16"))
		// Add the version field separately
		versionField, _ := fa.AddSubField("version", api.Kind_Uint8, datasource.WithTags("name:version"))

		lg := logger.DefaultLogger()

		replacerFunc, _ := rpl.replace(lg, ds, fa)
		data, _ := ds.NewPacketSingle()
		tc.putFunc(ipField, versionField, data)

		require.NotNil(t, replacerFunc)
		replacerFunc(data)

		fa = ds.GetFieldsWithTag(tc.name)[0]
		res, _ := fa.String(data)
		fmt.Println("res: ", res)

	}
}
