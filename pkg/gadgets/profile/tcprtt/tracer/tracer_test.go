//go:build linux
// +build linux

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

package tracer

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	utilstest "github.com/inspektor-gadget/inspektor-gadget/internal/test"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadgets/profile/tcprtt/types"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/histogram"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
)

func createTracer() *Tracer {
	return &Tracer{
		config: &Config{},
	}
}

func TestGadgetInstantiate(t *testing.T) {
	t.Parallel()

	gadget := &GadgetDesc{}
	tracer, err := gadget.NewInstance()
	require.Nil(t, err, "unexpected error creating instance")
	require.NotNil(t, tracer, "expected tracer")
}

func TestTracerInstallation(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer()
	err := tracer.install()
	require.Nil(t, err, "unexpected error installing tracer")

	tracer.close()
}

func TestTracerCloseIdempotent(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	tracer := createTracer()
	err := tracer.install()
	require.Nil(t, err, "unexpected error installing tracer")

	// Check that a double stop doesn't cause issues
	tracer.close()
	tracer.close()
}

func TestParseParams(t *testing.T) {
	t.Parallel()

	type expected struct {
		err    bool
		config *Config
	}

	gadget := &GadgetDesc{}

	testTable := []struct {
		description     string
		getGadgetParams func() *params.Params
		expected        expected
	}{
		{
			description: "milliseconds",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamMilliseconds).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					useMilliseconds: true,
				},
			},
		},
		{
			description: "by_local_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					localAddrHist: true,
				},
			},
		},
		{
			description: "by_remote_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					remoteAddrHist: true,
				},
			},
		},
		{
			description: "by_local_and_remote_address_err",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				params.Get(ParamByLocalAddress).Set("true")
				return params
			},
			expected: expected{
				err: true,
			},
		},
		{
			description: "filter_by_local_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("1.2.3.4")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddress: 0x04030201,
				},
			},
		},
		{
			description: "filter_by_remote_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddress).Set("192.168.0.1")
				return params
			},
			expected: expected{
				config: &Config{
					filterRemoteAddress: 0x0100A8C0,
				},
			},
		},
		{
			description: "filter_by_local_v6_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set("::ffff:c0a8:0001")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddressV6: [16]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1},
				},
			},
		},
		{
			description: "filter_by_remote_v6_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddressV6).Set("::ffff:c0a8:0001")
				return params
			},
			expected: expected{
				config: &Config{
					filterRemoteAddressV6: [16]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1},
				},
			},
		},
		{
			description: "filter_by_remote_and_filter_by_local_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("1.2.3.4")
				params.Get(ParamFilterRemoteAddress).Set("192.168.0.1")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddress:  0x04030201,
					filterRemoteAddress: 0x0100A8C0,
				},
			},
		},
		{
			description: "filter_by_remote_v4_and_filter_by_remote_v6_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddress).Set("192.168.0.1")
				params.Get(ParamFilterRemoteAddressV6).Set("::ffff:c0a8:0001")
				return params
			},
			expected: expected{
				err: true,
			},
		},
		{
			description: "filter_by_local_v4_and_filter_by_local_v6_address",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("192.168.0.1")
				params.Get(ParamFilterLocalAddressV6).Set("::ffff:c0a8:0001")
				return params
			},
			expected: expected{
				err: true,
			},
		},
		{
			description: "filter_by_remote_and_filter_by_local_address_sorted_by_local",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("1.2.3.4")
				params.Get(ParamFilterRemoteAddress).Set("192.168.0.1")
				params.Get(ParamByLocalAddress).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddress:  0x04030201,
					filterRemoteAddress: 0x0100A8C0,
					localAddrHist:       true,
				},
			},
		},
		{
			description: "filter_by_remote_and_filter_by_local_address_sorted_by_remote",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("1.2.3.4")
				params.Get(ParamFilterRemoteAddress).Set("192.168.0.1")
				params.Get(ParamByRemoteAddress).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddress:  0x04030201,
					filterRemoteAddress: 0x0100A8C0,
					remoteAddrHist:      true,
				},
			},
		},
		{
			description: "filter_by_remote_v6_and_filter_by_local_v6_address_sorted_by_local",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set("::ffff:c0a8:0001")
				params.Get(ParamFilterRemoteAddressV6).Set("::ffff:c0a8:0001")
				params.Get(ParamByLocalAddress).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddressV6:  [16]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1},
					filterRemoteAddressV6: [16]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1},
					localAddrHist:         true,
				},
			},
		},
		{
			description: "filter_by_remote_v6_and_filter_by_local_v6_address_sorted_by_remote",
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set("::ffff:c0a8:0001")
				params.Get(ParamFilterRemoteAddressV6).Set("::ffff:c0a8:0001")
				params.Get(ParamByRemoteAddress).Set("true")
				return params
			},
			expected: expected{
				config: &Config{
					filterLocalAddressV6:  [16]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1},
					filterRemoteAddressV6: [16]uint8{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0xff, 0xff, 0xc0, 0xa8, 0x0, 0x1},
					remoteAddrHist:        true,
				},
			},
		},
	}

	for _, test := range testTable {
		test := test
		t.Run(test.description, func(t *testing.T) {
			t.Parallel()

			tracer := createTracer()
			tracer.logger = log.StandardLogger()
			err := tracer.parseParams(test.getGadgetParams())

			if test.expected.err {
				require.NotNil(t, err, "expected error parsing params")
				return
			}

			require.Nil(t, err, "unexpected error parsing params")
			require.Equal(t, tracer.config, test.expected.config)
		})
	}
}

func TestRunWithResultV4(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const (
		// TODO: Use random ports once we support filtering by port.
		serverPort = 8080
	)

	// TODO: Use random IPs.
	serverIP := net.IPv4(127, 80, 80, 80)
	clientIP := net.IPv4(127, 127, 127, 127)
	startTCPServer(t, serverIP, serverPort, 4)

	gadget := &GadgetDesc{}

	runnerConfig := &utilstest.RunnerConfig{
		// This gadget works at host level not at network namespace
		// level, so we don't need to generate the events in an isolated
		// network namespace.
		HostNetwork: true,
	}

	type expectedResult struct {
		err             bool
		exactHistograms int
		minHistograms   int
		useMilliseconds bool // true if the unit is milliseconds, false if microseconds (gadget default)
		byRemoteAddr    string
		byLocalAddr     string
	}

	type testDefinition struct {
		getGadgetParams func() *params.Params
		timeout         time.Duration
		expectedResult  expectedResult
	}

	for name, test := range map[string]testDefinition{
		"with_default_params": {
			getGadgetParams: func() *params.Params {
				return gadget.ParamDescs().ToParams()
			},
			expectedResult: expectedResult{
				minHistograms: 1,
			},
		},
		"with_default_params_and_timeout": {
			timeout: 5 * time.Second,
			getGadgetParams: func() *params.Params {
				return gadget.ParamDescs().ToParams()
			},
			expectedResult: expectedResult{
				minHistograms: 1,
			},
		},
		"with_milliseconds": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamMilliseconds).Set("true")
				return params
			},
			expectedResult: expectedResult{
				minHistograms:   1,
				useMilliseconds: true,
			},
		},
		"by_local_addr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				return params
			},
			expectedResult: expectedResult{
				minHistograms: 1,
				byLocalAddr:   clientIP.String(),
			},
		},
		"by_remote_addr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				return params
			},
			expectedResult: expectedResult{
				minHistograms: 1,
				byRemoteAddr:  serverIP.String(),
			},
		},
		"filter_by_laddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set(clientIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
			},
		},
		"filter_by_invalid_laddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("0.1.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddress).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
			},
		},
		"filter_by_invalid_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddress).Set("0.1.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_laddr_and_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set(clientIP.String())
				params.Get(ParamFilterRemoteAddress).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
			},
		},
		"filter_by_laddr_and_raddr_msec": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set(clientIP.String())
				params.Get(ParamFilterRemoteAddress).Set(serverIP.String())
				params.Get(ParamMilliseconds).Set("true")
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				useMilliseconds: true,
			},
		},
		"filter_by_invalid_laddr_and_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("1.0.0.1")
				params.Get(ParamFilterRemoteAddress).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_laddr_and_invalid_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set(clientIP.String())
				params.Get(ParamFilterRemoteAddress).Set("1.0.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_invalid_laddr_and_invalid_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddress).Set("1.0.0.1")
				params.Get(ParamFilterRemoteAddress).Set("1.0.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"mix_by_local_and_filter_by_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				params.Get(ParamFilterRemoteAddress).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byLocalAddr:     clientIP.String(),
			},
		},
		"mix_by_local_and_filter_by_laddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				params.Get(ParamFilterLocalAddress).Set(clientIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byLocalAddr:     clientIP.String(),
			},
		},
		"mix_by_remote_and_filter_by_laddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				params.Get(ParamFilterLocalAddress).Set(clientIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byRemoteAddr:    serverIP.String(),
			},
		},
		"mix_by_remote_and_filter_by_raddr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				params.Get(ParamFilterRemoteAddress).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byRemoteAddr:    serverIP.String(),
			},
		},
		// TODO: Test mix cases with clients and servers with different IPs
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Create context
			gadgetCtx := newGadgetCtx(test.getGadgetParams(), test.timeout)
			defer gadgetCtx.Cancel()

			// Run the tracer in a goroutine
			tracer := createTracer()
			type output struct {
				result []byte
				err    error
			}
			out := make(chan output)
			go func() {
				r, err := tracer.RunWithResult(gadgetCtx)
				out <- output{r, err}
			}()

			// Wait for the tracer to be ready
			time.Sleep(2 * time.Second)

			// Generate the events
			runner := utilstest.NewRunnerWithTest(t, runnerConfig)
			utilstest.RunWithRunner(t, runner, func() error {
				connectTCPClient(t, clientIP, serverIP, serverPort, 4)
				return nil
			})

			// If needed, stop the tracer. Otherwise, simply wait for the result
			if test.timeout == 0 {
				// Wait for the tracer to capture the events
				time.Sleep(2 * time.Second)

				// Stop the tracer
				gadgetCtx.Cancel()
			}

			// Wait for the tracer to finish and produce a result
			ret := <-out

			// Validate errors
			if test.expectedResult.err {
				require.NotNil(t, ret.err, "expected error running tracer")
				require.Nil(t, ret.result, "available data when error occurred")
				return
			}
			assert.Nil(t, ret.err, "not expected error running tracer")

			// Unmarshal the result
			var result types.Report
			err := json.Unmarshal(ret.result, &result)
			require.Nil(t, err, "unmarshalling report")
			lHis := len(result.Histograms)

			// Dump the result
			for i, l := range result.Histograms {
				t.Logf("Result [%d/%d]:", i+1, lHis)
				t.Logf("AddrType %s - Addr %s - Avg %f", l.AddressType, l.Address, l.Average)
				t.Logf("Histogram: %s", l.Histogram)
			}

			// Validate the number of histograms
			if test.expectedResult.exactHistograms != 0 {
				require.Equal(t, test.expectedResult.exactHistograms, lHis,
					"invalid number of histograms")
			} else {
				// When we don't filter by address, we can't know how many
				// histograms will be generated. This is because the number of
				// histograms depends on the number of connections that are
				// established in the host during the test. Therefore, we can
				// only check that the number of histograms is greater or equal
				// than the minimum number of histograms we expect.
				require.GreaterOrEqual(t, lHis, test.expectedResult.minHistograms,
					"wrong number of histograms")
			}

			lAddrFound := false
			rAddrFound := false
			for _, h := range result.Histograms {
				// Validate unit
				var expectedUnit histogram.Unit
				if test.expectedResult.useMilliseconds {
					expectedUnit = histogram.UnitMilliseconds
				} else {
					expectedUnit = histogram.UnitMicroseconds
				}
				require.Equal(t, expectedUnit, h.Unit, "wrong unit for histogram")

				// Validate histogram contains at least one interval
				require.Greater(t, len(h.Intervals), int(0),
					"expecting at least one interval")

				// Validate histogram computed the average value
				// TODO: Verify this also when using milliseconds once the BPF
				// program will be able to report the total latencies between 0
				// and 1. Otherwise, the test will fail because the average
				// latency will always be 0 milliseconds, so there is no way to
				// verify that it was computed correctly.
				if !test.expectedResult.useMilliseconds {
					require.Greater(t, h.Average, float64(0))
				}

				// Validate histogram contains the expected address information
				if test.expectedResult.byLocalAddr != "" {
					require.Equal(t, types.AddressTypeLocal, h.AddressType)

					if h.Address == test.expectedResult.byLocalAddr {
						lAddrFound = true
					}
				} else if test.expectedResult.byRemoteAddr != "" {
					require.Equal(t, types.AddressTypeRemote, h.AddressType)

					if h.Address == test.expectedResult.byRemoteAddr {
						rAddrFound = true
					}
				} else {
					require.Equal(t, types.AddressTypeAll, h.AddressType)
					require.Equal(t, types.WildcardAddress, h.Address)
				}
			}
			if test.expectedResult.byLocalAddr != "" {
				require.True(t, lAddrFound,
					"expected to find histogram with local address %s", test.expectedResult.byLocalAddr)
			} else if test.expectedResult.byRemoteAddr != "" {
				require.True(t, rAddrFound,
					"expected to find histogram with remote address %s", test.expectedResult.byRemoteAddr)
			}
		})
	}
}

func TestRunWithResultV6(t *testing.T) {
	t.Parallel()

	utilstest.RequireRoot(t)

	const (
		serverPort = 8080
	)

	serverIP := net.ParseIP("::1")
	clientIP := net.ParseIP("::1")
	startTCPServer(t, serverIP, serverPort, 6)

	gadget := &GadgetDesc{}

	runnerConfig := &utilstest.RunnerConfig{
		// This gadget works at host level not at network namespace
		// level, so we don't need to generate the events in an isolated
		// network namespace.
		HostNetwork: true,
	}

	type expectedResult struct {
		err             bool
		exactHistograms int
		minHistograms   int
		useMilliseconds bool // true if the unit is milliseconds, false if microseconds (gadget default)
		byRemoteAddr    string
		byLocalAddr     string
	}

	type testDefinition struct {
		getGadgetParams func() *params.Params
		timeout         time.Duration
		expectedResult  expectedResult
	}

	for name, test := range map[string]testDefinition{
		"with_default_params": {
			getGadgetParams: func() *params.Params {
				return gadget.ParamDescs().ToParams()
			},
			expectedResult: expectedResult{
				minHistograms: 1,
			},
		},
		"with_default_params_and_timeout": {
			timeout: 5 * time.Second,
			getGadgetParams: func() *params.Params {
				return gadget.ParamDescs().ToParams()
			},
			expectedResult: expectedResult{
				minHistograms: 1,
			},
		},
		"by_local_addr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				return params
			},
			expectedResult: expectedResult{
				minHistograms: 1,
				byLocalAddr:   clientIP.String(),
			},
		},
		"by_remote_addr": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				return params
			},
			expectedResult: expectedResult{
				minHistograms: 1,
				byRemoteAddr:  serverIP.String(),
			},
		},
		"filter_by_laddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set(clientIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
			},
		},
		"filter_by_invalid_laddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set("0.1.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddressV6).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
			},
		},
		"filter_by_invalid_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterRemoteAddressV6).Set("0.1.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_laddr_v6_and_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set(clientIP.String())
				params.Get(ParamFilterRemoteAddressV6).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
			},
		},
		"filter_by_invalid_laddr_v6_and_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set("1.0.0.1")
				params.Get(ParamFilterRemoteAddressV6).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_laddr_v6_and_invalid_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set(clientIP.String())
				params.Get(ParamFilterRemoteAddressV6).Set("1.0.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"filter_by_invalid_laddr_v6_and_invalid_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamFilterLocalAddressV6).Set("1.0.0.1")
				params.Get(ParamFilterRemoteAddressV6).Set("1.0.0.1")
				return params
			},
			expectedResult: expectedResult{
				err: true,
			},
		},
		"mix_by_local_and_filter_by_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				params.Get(ParamFilterRemoteAddressV6).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byLocalAddr:     clientIP.String(),
			},
		},
		"mix_by_local_and_filter_by_laddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByLocalAddress).Set("true")
				params.Get(ParamFilterLocalAddressV6).Set(clientIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byLocalAddr:     clientIP.String(),
			},
		},
		"mix_by_remote_and_filter_by_laddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				params.Get(ParamFilterLocalAddressV6).Set(clientIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byRemoteAddr:    serverIP.String(),
			},
		},
		"mix_by_remote_and_filter_by_raddr_v6": {
			getGadgetParams: func() *params.Params {
				params := gadget.ParamDescs().ToParams()
				params.Get(ParamByRemoteAddress).Set("true")
				params.Get(ParamFilterRemoteAddressV6).Set(serverIP.String())
				return params
			},
			expectedResult: expectedResult{
				exactHistograms: 1,
				byRemoteAddr:    serverIP.String(),
			},
		},
		// TODO: Test mix cases with clients and servers with different IPs
	} {
		test := test

		t.Run(name, func(t *testing.T) {
			t.Parallel()

			// Create context
			gadgetCtx := newGadgetCtx(test.getGadgetParams(), test.timeout)
			defer gadgetCtx.Cancel()

			// Run the tracer in a goroutine
			tracer := createTracer()
			type output struct {
				result []byte
				err    error
			}
			out := make(chan output)
			go func() {
				r, err := tracer.RunWithResult(gadgetCtx)
				out <- output{r, err}
			}()

			// Wait for the tracer to be ready
			time.Sleep(2 * time.Second)

			// Generate the events
			runner := utilstest.NewRunnerWithTest(t, runnerConfig)
			utilstest.RunWithRunner(t, runner, func() error {
				connectTCPClient(t, clientIP, serverIP, serverPort, 6)
				return nil
			})

			// If needed, stop the tracer. Otherwise, simply wait for the result
			if test.timeout == 0 {
				// Wait for the tracer to capture the events
				time.Sleep(2 * time.Second)

				// Stop the tracer
				gadgetCtx.Cancel()
			}

			// Wait for the tracer to finish and produce a result
			ret := <-out

			// Validate errors
			if test.expectedResult.err {
				require.NotNil(t, ret.err, "expected error running tracer")
				require.Nil(t, ret.result, "available data when error occurred")
				return
			}
			assert.Nil(t, ret.err, "not expected error running tracer")

			// Unmarshal the result
			var result types.Report
			err := json.Unmarshal(ret.result, &result)
			require.Nil(t, err, "unmarshalling report")
			lHis := len(result.Histograms)

			// Dump the result
			for i, l := range result.Histograms {
				t.Logf("Result [%d/%d]:", i+1, lHis)
				t.Logf("AddrType %s - Addr %s - Avg %f", l.AddressType, l.Address, l.Average)
				t.Logf("Histogram: %s", l.Histogram)
			}

			// Validate the number of histograms
			if test.expectedResult.exactHistograms != 0 {
				require.Equal(t, test.expectedResult.exactHistograms, lHis,
					"invalid number of histograms")
			} else {
				// When we don't filter by address, we can't know how many
				// histograms will be generated. This is because the number of
				// histograms depends on the number of connections that are
				// established in the host during the test. Therefore, we can
				// only check that the number of histograms is greater or equal
				// than the minimum number of histograms we expect.
				require.GreaterOrEqual(t, lHis, test.expectedResult.minHistograms,
					"wrong number of histograms")
			}

			lAddrFound := false
			rAddrFound := false
			for _, h := range result.Histograms {
				// Validate unit
				var expectedUnit histogram.Unit
				if test.expectedResult.useMilliseconds {
					expectedUnit = histogram.UnitMilliseconds
				} else {
					expectedUnit = histogram.UnitMicroseconds
				}
				require.Equal(t, expectedUnit, h.Unit, "wrong unit for histogram")

				// Validate histogram contains at least one interval
				require.Greater(t, len(h.Intervals), int(0),
					"expecting at least one interval")

				// Validate histogram computed the average value
				// TODO: Verify this also when using milliseconds once the BPF
				// program will be able to report the total latencies between 0
				// and 1. Otherwise, the test will fail because the average
				// latency will always be 0 milliseconds, so there is no way to
				// verify that it was computed correctly.
				if !test.expectedResult.useMilliseconds {
					require.Greater(t, h.Average, float64(0))
				}

				// Validate histogram contains the expected address information
				if test.expectedResult.byLocalAddr != "" {
					require.Equal(t, types.AddressTypeLocal, h.AddressType)

					if h.Address == test.expectedResult.byLocalAddr {
						lAddrFound = true
					}
				} else if test.expectedResult.byRemoteAddr != "" {
					require.Equal(t, types.AddressTypeRemote, h.AddressType)

					if h.Address == test.expectedResult.byRemoteAddr {
						rAddrFound = true
					}
				} else {
					require.Equal(t, types.AddressTypeAll, h.AddressType)
					require.Equal(t, types.WildcardAddress, h.Address)
				}
			}
			if test.expectedResult.byLocalAddr != "" {
				require.True(t, lAddrFound,
					"expected to find histogram with local address %s", test.expectedResult.byLocalAddr)
			} else if test.expectedResult.byRemoteAddr != "" {
				require.True(t, rAddrFound,
					"expected to find histogram with remote address %s", test.expectedResult.byRemoteAddr)
			}
		})
	}
}

func verifyNetError(t *testing.T, err error) {
	if err == nil {
		return
	}

	// If possible, get more detailed information about the error
	var oPErr *net.OpError
	if errors.As(err, &oPErr) {
		require.Nil(t, oPErr.Err)
	}

	// Make test fail anyway
	require.Nil(t, err)
}

func startTCPServer(t *testing.T, serverIP net.IP, serverPort, family int) {
	t.Helper()

	// "[]" are required for IPv6 addresses.
	l, err := net.Listen(fmt.Sprintf("tcp%d", family), fmt.Sprintf("[%s]:%d", serverIP, serverPort))
	verifyNetError(t, err)
	require.NotNil(t, l, "expected listener")
	t.Cleanup(func() {
		l.Close()
	})

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				require.Contains(t, err.Error(), net.ErrClosed.Error())
				return
			}

			go func(conn net.Conn) {
				defer conn.Close()

				// Read the data from the connection
				buf := make([]byte, 1024)
				n, err := conn.Read(buf)
				if err != nil {
					require.Contains(t, err.Error(), net.ErrClosed.Error())
					return
				}
				require.Greater(t, n, 0)

				// Write the data back to the connection
				response := fmt.Sprintf("Echo: %s", string(buf))
				n, err = conn.Write([]byte(response))
				if err != nil {
					require.Contains(t, err.Error(), net.ErrClosed.Error())
					return
				}
				require.Equal(t, len(response), n)
			}(conn)
		}
	}()
}

func connectTCPClient(t *testing.T, clientIP net.IP, remoteIP net.IP, remotePort, family int) {
	t.Helper()

	const (
		// Number of parallel connections to establish
		parallelConnections = 5
	)

	// Connect multiple times to the server to generate more traffic
	wg := sync.WaitGroup{}
	for i := 0; i < parallelConnections; i++ {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			// ResolveTCPAddr will assign a random port to the client
			tcpClient, err := net.ResolveTCPAddr(fmt.Sprintf("tcp%d", family), fmt.Sprintf("[%s]:0", clientIP.String()))
			verifyNetError(t, err)
			require.NotNil(t, tcpClient)

			tcpRemote := &net.TCPAddr{
				IP:   remoteIP,
				Port: remotePort,
			}

			conn, err := net.DialTCP(fmt.Sprintf("tcp%d", family), tcpClient, tcpRemote)
			verifyNetError(t, err)
			require.NotNil(t, conn, "expected connection")
			defer conn.Close()

			// Send dummy messages to the server to generate traffic
			msg := fmt.Sprintf("Hello %d from %s:%d", i, tcpClient.IP, tcpClient.Port)
			n, err := conn.Write([]byte(msg))
			require.Nil(t, err)
			require.Equal(t, len(msg), n)

			// Read the response from the server
			received := make([]byte, 1024)
			n, err = conn.Read(received)
			require.Nil(t, err)
			require.Greater(t, n, 0)
		}(i)
	}

	// Wait for all connections to be closed
	wg.Wait()
}

func newGadgetCtx(gadgetParams *params.Params, timeout time.Duration) *gadgetcontext.GadgetContext {
	return gadgetcontext.New(
		context.Background(),
		"",
		nil,
		nil,
		nil,
		gadgetParams,
		nil,
		nil,
		nil,
		log.StandardLogger(),
		timeout,
	)
}
