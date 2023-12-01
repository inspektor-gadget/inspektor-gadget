// Copyright 2019-2021 The Inspektor Gadget authors
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

package main

import (
	"bytes"
	"testing"

	"github.com/inspektor-gadget/inspektor-gadget/cmd/common"
	grpcruntime "github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/grpc"
)

func TestPrintOnly(t *testing.T) {
	grpcRuntime = grpcruntime.New(grpcruntime.WithConnectUsingK8SProxy)
	runtimeGlobalParams = grpcRuntime.GlobalParamDescs().ToParams()

	cmd := rootCmd
	common.AddFlags(cmd, runtimeGlobalParams, nil, grpcRuntime)
	cmd.SetArgs([]string{"deploy", "--print-only"})

	var stdErr bytes.Buffer
	cmd.SetErr(&stdErr)
	cmd.Execute()
	if stdErr.Len() != 0 {
		t.Fatalf("Error while running command: %s", stdErr.String())
	}
}
