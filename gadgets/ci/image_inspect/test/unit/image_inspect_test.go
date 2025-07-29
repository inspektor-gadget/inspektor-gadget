// Copyright 2025 The Inspektor Gadget authors
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

package tests

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	gadgettesting "github.com/inspektor-gadget/inspektor-gadget/gadgets/testing"
	gadgetcontext "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-context"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
	apihelpers "github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api-helpers"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/operators"
	ocihandler "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/oci-handler"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/params"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/runtime/local"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/testing/gadgetrunner"

	_ "github.com/inspektor-gadget/inspektor-gadget/pkg/operators/ebpf"
)

type extraInfoMap struct {
	Name string
	Type string
}

type extraInfoProgram struct {
	Section string
	Source  string
}

type extraInfoVariable struct {
	Name   string
	Offset uint64
	Size   uint64
	Map    string
}

func TestInspectCmd(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	t.Parallel()

	info, err := extractGadgetInfo(true)
	if err != nil {
		t.Fatalf("Error getting gadget info: %v\n", err)
	}

	// Validate keys
	expectedKeys := []string{
		"ebpf.flowchart",
		"ebpf.maps",
		"ebpf.programs",
		"ebpf.sections",
		"ebpf.sequence",
		"ebpf.variables",
		"oci.created",
		"oci.digest",
		"oci.manifest",
		"oci.metadata",
		"oci.repository",
		"oci.tag",
	}
	extraInfoKeys := make([]string, 0, len(info.ExtraInfo.Data))
	for k := range info.ExtraInfo.Data {
		extraInfoKeys = append(extraInfoKeys, k)
	}
	sort.Strings(extraInfoKeys)
	sort.Strings(expectedKeys)
	require.Equal(t, expectedKeys, extraInfoKeys, "extra info keys mismatch")

	// Validate eBPF programs
	validateExtraInfoValue(t, "ebpf.programs", info.ExtraInfo.Data["ebpf.programs"], []string{"program1", "program2", "program3", "program4"})

	// Validate eBPF maps
	validateExtraInfoValue(t, "ebpf.maps", info.ExtraInfo.Data["ebpf.maps"], []extraInfoMap{
		{Name: "map1", Type: "Hash"},
		{Name: "map2", Type: "Hash"},
	})

	// Validate eBPF variables
	validateExtraInfoValue(t, "ebpf.variables", info.ExtraInfo.Data["ebpf.variables"], []string{
		"gadget_mapiter_qdisc___map1", "gadget_param_ifindex", "gadget_param_targ_ms", "ifindex", "targ_ms",
	})

	// Validate flowchart
	expectedFlowchart := `flowchart LR
map1[("map1")]
map2[("map2")]
consume_skb -- "Lookup+Delete" --> map2
consume_skb["consume_skb"]
kfree_skb["kfree_skb"]
qdisc_dequeue -- "Lookup+Update" --> map1
qdisc_dequeue["qdisc_dequeue"]
qdisc_enqueue -- "Update" --> map2
qdisc_enqueue["qdisc_enqueue"]
`
	validateExtraInfoValue(t, "ebpf.flowchart", info.ExtraInfo.Data["ebpf.flowchart"], expectedFlowchart)

	// Validate sequence chart
	expectedSequence := `sequenceDiagram
box eBPF Programs
participant consume_skb
participant kfree_skb
participant qdisc_dequeue
participant qdisc_enqueue
end
box eBPF Maps
participant map2
participant map1
end
consume_skb->>map2: Lookup
consume_skb->>map2: Delete
qdisc_dequeue->>map1: Lookup
qdisc_dequeue->>map1: Update
qdisc_enqueue->>map2: Update
`
	validateExtraInfoValue(t, "ebpf.sequence", info.ExtraInfo.Data["ebpf.sequence"], expectedSequence)

	// Validate OCI extra info
	validateExtraInfoValue(t, "oci.created", info.ExtraInfo.Data["oci.created"], nil)
	validateExtraInfoValue(t, "oci.digest", info.ExtraInfo.Data["oci.digest"], nil)
	validateExtraInfoValue(t, "oci.repository", info.ExtraInfo.Data["oci.repository"], nil)
	validateExtraInfoValue(t, "oci.tag", info.ExtraInfo.Data["oci.tag"], nil)
	validateExtraInfoValue(t, "oci.manifest", info.ExtraInfo.Data["oci.manifest"], nil)

	// Validate OCI metadata
	expectedMetadata := `name: image_inspect
description: Example gadget
homepageURL: http://mygadget.com
documentationURL: https://mygadget.com/docs
sourceURL: https://github.com/my-org/mygadget/
datasources:
  open:
    fields:
      comm:
        annotations:
          description: Name of the process opening a file
          template: comm
      filename:
        annotations:
          columns.width: "64"
          description: Path of the file being opened
      pid:
        annotations:
          description: PID of the process opening a file
          template: pid
  qdisc:
    fields:
      latency:
        annotations:
          description: 'TODO: Fill field description'
      unused:
        annotations:
          description: 'TODO: Fill field description'
params:
  ebpf:
    ifindex:
      key: ifindex
      defaultValue: ""
      description: 'TODO: Fill parameter description'
    targ_ms:
      key: targ_ms
      defaultValue: ""
      description: 'TODO: Fill parameter description'
`
	validateExtraInfoValue(t, "oci.metadata", info.ExtraInfo.Data["oci.metadata"], expectedMetadata)
}

func TestExtraInfoLeak(t *testing.T) {
	gadgettesting.InitUnitTest(t)
	t.Parallel()

	info, err := extractGadgetInfo(false)
	require.Nil(t, err, "getting gadget info: %v\n", err)

	// Validate extraInfo is empty
	require.Nil(t, info.ExtraInfo, "extra info should be nil")
}

func extractGadgetInfo(extraInfo bool) (*api.GadgetInfo, error) {
	image := gadgetrunner.GetGadgetImageName("ci/image_inspect")
	ocihandlerOp := ocihandler.New()

	opGlobalParams := make(map[string]*params.Params)
	opGlobalParams["oci"] = apihelpers.ToParamDescs(ocihandlerOp.GlobalParams()).ToParams()
	verifyImage := "false"
	if verifyImage == "true" || verifyImage == "false" {
		opGlobalParams["oci"].Set("verify-image", verifyImage)
	} else {
		return nil, fmt.Errorf("Environment variable IG_VERIFY_IMAGE must be set to \"true\" or \"false\", got: %s", verifyImage)
	}

	runtime := local.New()
	runtimeParams := runtime.ParamDescs().ToParams()

	ops := make([]operators.DataOperator, 0)
	err := ocihandlerOp.Init(opGlobalParams["oci"])
	if err != nil {
		return nil, fmt.Errorf("Error initializing OCI handler: %w\n", err)
	}
	ops = append(ops, ocihandlerOp)

	gadgetCtx := gadgetcontext.New(
		context.Background(),
		image,
		gadgetcontext.WithDataOperators(ops...),
		gadgetcontext.WithUseInstance(false),
		gadgetcontext.IncludeExtraInfo(extraInfo),
	)

	ociParams := apihelpers.ToParamDescs(ocihandlerOp.InstanceParams()).ToParams()
	paramValueMap := make(map[string]string)
	ociParams.CopyToMap(paramValueMap, "operator.oci.")

	info, err := runtime.GetGadgetInfo(gadgetCtx, runtimeParams, paramValueMap)
	if err != nil {
		return nil, fmt.Errorf("Error getting gadget info: %w\n", err)
	}
	return info, nil
}

func validateExtraInfoValue(t *testing.T, key string, extraInfo *api.GadgetInspectAddendum, expected any) {
	t.Helper()

	switch key {
	case "ebpf.programs":
		var got []extraInfoProgram
		require.NoError(t, json.Unmarshal(extraInfo.Content, &got), "unmarshal ebpf.programs failed")
		require.Equal(t, "application/json", extraInfo.ContentType, "ebpf.programs: expected type mismatch")
		var gotNames []string
		for _, v := range got {
			gotNames = append(gotNames, v.Section)
		}
		require.Len(t, gotNames, len(expected.([]string)))
		for _, name := range expected.([]string) {
			require.Contains(t, gotNames, name)
		}

	case "ebpf.maps":
		var got []extraInfoMap
		require.NoError(t, json.Unmarshal(extraInfo.Content, &got), "unmarshal ebpf.maps failed")
		require.Equal(t, "application/json", extraInfo.ContentType, "ebpf.maps: expected type mismatch")
		sort.Slice(got, func(i, j int) bool { return got[i].Name < got[j].Name })
		require.Equal(t, expected, got)

	case "ebpf.variables":
		var got []extraInfoVariable
		require.NoError(t, json.Unmarshal(extraInfo.Content, &got), "unmarshal ebpf.variables failed")
		require.Equal(t, "application/json", extraInfo.ContentType, "ebpf.variables: expected type mismatch")
		var gotNames []string
		for _, v := range got {
			gotNames = append(gotNames, v.Name)
		}
		require.Len(t, gotNames, len(expected.([]string)))
		for _, name := range expected.([]string) {
			require.Contains(t, gotNames, name)
		}

	case "ebpf.flowchart", "ebpf.sequence":
		require.Equal(t, "text/mermaid", extraInfo.ContentType, "%s: expected []byte", key)
		require.Equal(t, expected.(string), string(extraInfo.Content), "%s mismatch", key)

	case "oci.created", "oci.digest", "oci.repository", "oci.tag":
		require.Equal(t, "text/plain", extraInfo.ContentType, "%s: expected []byte", key)
		require.NotNil(t, extraInfo.Content, "%s: expected non-nil content", key)

	case "oci.manifest":
		require.Equal(t, "application/json", extraInfo.ContentType, "%s: expected []byte", key)
		require.NotNil(t, extraInfo.Content, "%s: expected non-nil content", key)

	case "oci.metadata":
		require.Equal(t, "text/yaml", extraInfo.ContentType, "%s: expected []byte", key)
		require.Equal(t, expected, string(extraInfo.Content), "%s mismatch", key)

	default:
		t.Fatalf("unexpected key: %s", key)
	}
}
