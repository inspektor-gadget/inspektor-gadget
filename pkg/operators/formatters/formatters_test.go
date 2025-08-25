// Copyright 2025 The Inspektor Gadget authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
package formatters

import (
	"fmt"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/logger"
	ebpftypes "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf/types"
)

func TestGeneral(t *testing.T) {
	type testCaseDatum struct {
		value      any
		expected   any
		annotation map[string]string
		arch       string
		ok         bool
	}

	type testCase struct {
		name     string
		kind     api.Kind
		epbftype string
		putFunc  func(fa datasource.FieldAccessor, data datasource.Data, value any)
		data     []testCaseDatum
	}

	testCases := []testCase{
		{
			name:     "timestamp",
			kind:     api.Kind_Uint64,
			epbftype: ebpftypes.TimestampTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint64(data, value.(uint64))
			},
			data: []testCaseDatum{
				{
					value:    uint64(1e9), // 1.5 seconds
					ok:       true,
					expected: getFormattedTimeFromBootTime(1e9, "2006-01-02T15:04:05.000000000Z07:00"),
				},
				{
					value:    uint64(45 * 60 * 1e9), // 45 minutes
					ok:       true,
					expected: getFormattedTimeFromBootTime(45*60*1e9, "02-01-2006 15:04:05"),
					annotation: map[string]string{
						"formatters.timestamp.target": "walltime",
						"formatters.timestamp.format": "02-01-2006 15:04:05",
					},
				},
				{
					value:    uint64(2 * 60 * 60 * 1e9), // 2 hours
					ok:       true,
					expected: getFormattedTimeFromBootTime(2*60*60*1e9, "03:04:05 PM"),
					annotation: map[string]string{
						"formatters.timestamp.target": "walltime",
						"formatters.timestamp.format": "03:04:05 PM",
					},
				},
				{
					value:    uint64(5*60*60*1e9 + 30*1e9), // 5 hours, 30 seconds
					ok:       true,
					expected: getFormattedTimeFromBootTime(5*60*60*1e9+30*1e9, "Monday, January 2, 2006 at 15:04:05 MST"),
					annotation: map[string]string{
						"formatters.timestamp.target": "walltime",
						"formatters.timestamp.format": "Monday, January 2, 2006 at 15:04:05 MST",
					},
				},
				{
					value:    uint64(9*60*60*1e9 + 15*60*1e9), // 9 hours, 15 minutes
					ok:       true,
					expected: getFormattedTimeFromBootTime(9*60*60*1e9+15*60*1e9, "20060102_150405"),
					annotation: map[string]string{
						"formatters.timestamp.target": "walltime",
						"formatters.timestamp.format": "20060102_150405",
					},
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
			data: []testCaseDatum{
				{
					value:      uint32(9),
					ok:         true,
					expected:   "SIGKILL",
					annotation: nil,
				},
				{
					value:      uint32(15),
					ok:         true,
					expected:   "SIGTERM",
					annotation: map[string]string{"formatters.signal.target": "friendly"},
				},
				{
					value:      uint32(2),
					ok:         true,
					expected:   "SIGINT",
					annotation: map[string]string{"formatters.signal.target": "interrupt"},
				},
				{
					value:      uint32(11),
					ok:         true,
					expected:   "SIGSEGV",
					annotation: map[string]string{"formatters.signal.target": "crash"},
				},
				{
					value:      uint32(1),
					ok:         true,
					expected:   "SIGHUP",
					annotation: map[string]string{"formatters.signal.target": "standard"},
				},
				{
					value:    uint32(32),
					expected: "signal#32",
					ok:       true,
				},
				{
					value:    uint32(100),
					expected: "signal#100",
					ok:       true,
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
			data: []testCaseDatum{
				{
					value:      uint32(2),
					ok:         true,
					expected:   "ENOENT",
					annotation: nil,
				},
				{
					value:      uint32(13),
					ok:         true,
					expected:   "EACCES",
					annotation: map[string]string{"formatters.errno.target": "description"},
				},
				{
					value:      uint32(5),
					ok:         true,
					expected:   "EIO",
					annotation: map[string]string{"formatters.errno.target": "io_error"},
				},
				{
					value:      uint32(28),
					ok:         true,
					expected:   "ENOSPC",
					annotation: map[string]string{"formatters.errno.target": "storage"},
				},
				{
					value:      uint32(110),
					ok:         true,
					expected:   "ETIMEDOUT",
					annotation: map[string]string{"formatters.errno.target": "timeout"},
				},
				{
					value:    uint32(134),
					expected: "error#134",
					ok:       true,
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
			data: []testCaseDatum{
				{
					value:      uint64(1e6),
					ok:         true,
					expected:   "1.0 MB",
					annotation: nil,
				},
				{
					value:      uint64(1e9),
					ok:         true,
					expected:   "1.0 GB",
					annotation: map[string]string{"formatters.bytes.target": "humanreadable"},
				},
				{
					value:      uint64(512),
					ok:         true,
					expected:   "512 B",
					annotation: map[string]string{"formatters.bytes.target": "small_units"},
				},
				{
					value:      uint64(5 * 1e12), // 5 Terabytes
					ok:         true,
					expected:   "5.0 TB",
					annotation: map[string]string{"formatters.bytes.target": "large_units"},
				},
				{
					value:      uint64(256 * 1e6), // 256 Megabytes
					ok:         true,
					expected:   "256 MB",
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
			data: []testCaseDatum{
				{
					value:      uint64(3*time.Second + 250*time.Millisecond),
					ok:         true,
					expected:   "3.25s",
					annotation: nil,
				},
				{
					value:      uint64(5 * time.Minute),
					ok:         true,
					expected:   "5m0s",
					annotation: map[string]string{"formatters.duration.target": "compact"},
				},
				{
					value:      uint64(150 * time.Millisecond),
					ok:         true,
					expected:   "150.00ms",
					annotation: map[string]string{"formatters.duration.target": "milliseconds"},
				},
				{
					value:      uint64(2*time.Hour + 30*time.Minute),
					ok:         true,
					expected:   "2h30m0s",
					annotation: map[string]string{"formatters.duration.target": "longform"},
				},
				{
					value:      uint64(10 * time.Microsecond), // < 1 milli second
					ok:         true,
					expected:   "10.00µs",
					annotation: nil,
				},
				{
					value:      uint64(10 * time.Nanosecond), // < 1 micro second
					ok:         true,
					expected:   "10ns",
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
			data: []testCaseDatum{
				// AMD64 Test Cases
				{
					value:      uint64(60),
					ok:         true,
					expected:   "SYS_EXIT",
					arch:       "amd64",
					annotation: map[string]string{"formatters.syscall.target": "systarget"},
				},
				{
					value:      uint64(80),
					ok:         true,
					expected:   "SYS_CHDIR",
					arch:       "amd64",
					annotation: nil,
				},
				{
					value:      uint64(3),
					ok:         true,
					expected:   "SYS_CLOSE",
					arch:       "amd64",
					annotation: map[string]string{"formatters.syscall.target": "shortname"},
				},
				{
					value:      uint64(292),
					ok:         true,
					expected:   "SYS_DUP3",
					arch:       "amd64",
					annotation: nil,
				},
				{
					value:      uint64(300),
					ok:         true,
					expected:   "SYS_FANOTIFY_INIT",
					arch:       "amd64",
					annotation: map[string]string{"formatters.syscall.target": "detailed"},
				},
				{
					value:    uint64(1e6),
					ok:       true,
					expected: "SYS_UNKNOWN",
					arch:     "amd64",
				},

				// ARM64 Test Cases
				{
					value:      uint64(64),
					ok:         true,
					expected:   "SYS_WRITE",
					arch:       "arm64",
					annotation: nil,
				},
				{
					value:      uint64(211),
					ok:         true,
					expected:   "SYS_SENDMSG",
					arch:       "arm64",
					annotation: nil,
				},
				{
					value:      uint64(147),
					ok:         true,
					expected:   "SYS_SETRESUID",
					arch:       "arm64",
					annotation: map[string]string{"formatters.syscall.target": "user"},
				},
				{
					value:      uint64(210),
					ok:         true,
					expected:   "SYS_SHUTDOWN",
					arch:       "arm64",
					annotation: nil,
				},
				{
					value:      uint64(77),
					ok:         true,
					expected:   "SYS_TEE",
					arch:       "arm64",
					annotation: map[string]string{"formatters.syscall.target": "network"},
				},
				{
					value:    uint64(1e6),
					ok:       true,
					expected: "SYS_UNKNOWN",
					arch:     "arm64",
				},
			},
		},
		{
			name:     "file_mode",
			kind:     api.Kind_Uint32,
			epbftype: ebpftypes.FileModeTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint32(data, value.(uint32))
			},
			data: []testCaseDatum{
				{
					value:      uint32(0o644), // -rw-r--r--
					ok:         true,
					expected:   "-rw-r--r--",
					annotation: nil,
				},
				{
					value:      uint32(0o755), // -rwxr-xr-x
					ok:         true,
					expected:   "-rwxr-xr-x",
					annotation: map[string]string{"formatters.file_mode.target": "permissions"},
				},
				{
					value:      uint32(0o777), // -rwxrwxrwx
					ok:         true,
					expected:   "-rwxrwxrwx",
					annotation: nil,
				},
				{
					value:      uint32(0o600), // -rw-------
					ok:         true,
					expected:   "-rw-------",
					annotation: map[string]string{"formatters.file_mode.target": "owner_only"},
				},
				{
					value:      uint32(0o444), // -r--r--r--
					ok:         true,
					expected:   "-r--r--r--",
					annotation: nil,
				},
			},
		},
		{
			name:     "file_flags",
			kind:     api.Kind_Uint32,
			epbftype: ebpftypes.FileFlagsTypeName,
			putFunc: func(fa datasource.FieldAccessor, data datasource.Data, value any) {
				fa.PutUint32(data, value.(uint32))
			},
			data: []testCaseDatum{
				{
					value:      uint32(0), // O_RDONLY
					ok:         true,
					expected:   "O_RDONLY",
					annotation: nil,
				},
				{
					value:      uint32(1), // O_WRONLY
					ok:         true,
					expected:   "O_WRONLY",
					annotation: nil,
				},
				{
					value:      uint32(2), // O_RDWR
					ok:         true,
					expected:   "O_RDWR",
					annotation: nil,
				},
				{
					value:      uint32(0o100), // O_CREAT (64 + 0 for O_RDONLY)
					ok:         true,
					expected:   "O_RDONLY|O_CREAT",
					annotation: nil,
				},
				{
					value:      uint32(0o101), // O_CREAT | O_WRONLY (64 + 1)
					ok:         true,
					expected:   "O_WRONLY|O_CREAT",
					annotation: map[string]string{"formatters.file_flags.target": "write_flags"},
				},
				{
					value:      uint32(0o1102), // O_CREAT | O_TRUNC | O_RDWR (64 + 512 + 2)
					ok:         true,
					expected:   "O_RDWR|O_CREAT|O_TRUNC",
					annotation: nil,
				},
				{
					value:      uint32(0o2000), // O_APPEND only (1024 + 0 for O_RDONLY)
					ok:         true,
					expected:   "O_RDONLY|O_APPEND",
					annotation: map[string]string{"formatters.file_flags.target": "append_mode"},
				},
			},
		},
	}

	for _, tc := range testCases {
		for _, datum := range tc.data {
			t.Run(
				fmt.Sprintf("%s input: %v expected output: %v", tc.name, datum.value, datum.expected),
				func(t *testing.T) {
					if datum.arch != "" && runtime.GOARCH != datum.arch {
						t.Skip("skipping test on non-" + datum.arch + " arch")
					}
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

					if !datum.ok {
						require.Error(t, err)
						return
					}
					require.NoError(t, err)

					var formattedField datasource.FieldAccessor
					if customTargetName, ok := datum.annotation["formatters."+tc.name+".target"]; ok {
						formattedField = ds.GetField(customTargetName)
					} else {
						formattedField = ds.GetField(tc.name)
					}
					require.NotNil(t, formattedField, "formatted field not found for "+tc.name)
					res, err := formattedField.String(data)
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
		ok         bool
		version    uint8
	}

	tests := []testDataL3{
		// IPv4 test cases
		{
			rawIP:      ipToBytes("192.168.10.10", 4),
			expectedIP: "192.168.10.10",
			ok:         true,
			version:    4,
		},
		{
			rawIP:      ipToBytes("0.113.45", 4),
			expectedIP: "0.113.45",
			ok:         false,
			version:    4,
		},
		{
			rawIP:      ipToBytes("8.8", 4),
			expectedIP: "8.8",
			ok:         false,
			version:    4,
		},

		// IPv6 test cases
		{
			rawIP:      ipToBytes("2001:db8::1", 6),
			expectedIP: "2001:db8::1",
			ok:         true,
			version:    6,
		},
		{
			rawIP:      ipToBytes("fe80::1", 6),
			expectedIP: "fe80::1",
			ok:         true,
			version:    6,
		},
		{
			rawIP:      ipToBytes("::1", 6),
			expectedIP: "::1",
			ok:         true,
			version:    6,
		},
		{
			rawIP:      ipToBytes("::1", 6),
			expectedIP: "::1",
			ok:         false,
			version:    10, // invalid version
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
				versionField.PutUint8(data, td.version)

				err = replacerFunc(data)
				if !td.ok {
					require.Error(t, err)
					return
				}
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
		ok               bool
		version          int
	}

	tests := []testDataL4{
		{
			rawIP:            ipToBytes("192.168.10.10", 4),
			port:             8080,
			expectedEndpoint: "192.168.10.10:8080",
			protoNumber:      uint16Ptr(6),
			expectedProto:    stringPtr("TCP"),
			ok:               true,
			version:          4,
		},
		{
			rawIP:            ipToBytes("10.0.0.1", 4),
			port:             80,
			expectedEndpoint: "10.0.0.1:80",
			protoNumber:      nil,
			expectedProto:    nil,
			ok:               true,
			version:          4,
		},
		{
			rawIP:            ipToBytes("172.16.5.100", 4),
			port:             0,
			expectedEndpoint: "172.16.5.100:0",
			protoNumber:      uint16Ptr(28),
			expectedProto:    stringPtr("IRTP"),
			ok:               true,
			version:          4,
		},
		{
			rawIP:            ipToBytes("203.0.113.45", 4),
			port:             1234,
			expectedEndpoint: "203.0.113.45:1234",
			protoNumber:      uint16Ptr(42),
			expectedProto:    stringPtr("SDRP"),
			ok:               true,
			version:          4,
		},
		{
			rawIP:            ipToBytes("2001:db8::5", 6),
			port:             8888,
			expectedEndpoint: "2001:db8::5:8888",
			protoNumber:      uint16Ptr(78),
			expectedProto:    stringPtr("WB-MON"),
			ok:               true,
			version:          6,
		},
		{
			rawIP:            ipToBytes("2607:f8b0:4005:809::200e", 6),
			port:             5060,
			expectedEndpoint: "2607:f8b0:4005:809::200e:5060",
			protoNumber:      uint16Ptr(126),
			expectedProto:    stringPtr("CRTP"),
			ok:               true,
			version:          6,
		},
		{
			rawIP:            ipToBytes("fe80::1", 6),
			port:             5353,
			expectedEndpoint: "fe80::1:5353",
			protoNumber:      uint16Ptr(141),
			expectedProto:    stringPtr("WESP"),
			ok:               true,
			version:          6,
		},
		{
			rawIP:            ipToBytes("2607:f8b0:4005:809::200e", 6),
			port:             22,
			expectedEndpoint: "2607:f8b0:4005:809::200e:22",
			protoNumber:      uint16Ptr(1000),
			expectedProto:    stringPtr("proto#1000"),
			ok:               true,
			version:          6,
		},
		{
			rawIP:            ipToBytes("2607:f8b0:4005:809::200e", 6),
			port:             4,
			expectedEndpoint: "2607:f8b0:4005:809::200e",
			protoNumber:      uint16Ptr(1000),
			expectedProto:    stringPtr("TCP"),
			ok:               false,
			version:          10, // invalid version
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
				versionField.PutUint8(data, uint8(td.version))
				portField.PutUint16(data, td.port)
				if td.protoNumber != nil {
					protoRawField.PutUint16(data, *td.protoNumber)
				}

				err = replacerFunc(data)

				if !td.ok {
					require.Error(t, err)
					return
				}

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

func ipToBytes(ipStr string, version int) []byte {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return nil
	}

	if version == 4 && ip.To4() != nil {
		return append([]byte(ip.To4()), make([]byte, 12)...)
	} else if version == 6 && ip.To16() != nil {
		return ip.To16()
	}
	return nil
}

func getFormattedTimeFromBootTime(bootTime uint64, format string) string {
	adjusted := gadgets.WallTimeFromBootTime(bootTime)
	t := time.Unix(0, int64(adjusted))
	return t.Format(format)
}
