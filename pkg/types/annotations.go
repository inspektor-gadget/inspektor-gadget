// Copyright 2024 The Inspektor Gadget authors
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

package types

import (
	"strings"

	metadatav1 "github.com/inspektor-gadget/inspektor-gadget/pkg/metadata/v1"
)

func ApplyAnnotationsTemplate(templateAnn string, dst map[string]string) bool {
	template, ok := annotationsTemplates[templateAnn]

	for k, v := range template {
		dst[k] = v
	}

	return ok
}

func AppplyAnnotationsTemplateForType(typeName string, dst map[string]string) bool {
	switch typeName {
	case CommTypeName,
		UidTypeName,
		GidTypeName,
		PidTypeName,
		TidTypeName,
		TimestampTypeName,
		MntNsTypeName,
		NetNsTypeName,
		PcommTypeName,
		PpidTypeName:
		return ApplyAnnotationsTemplate(strings.TrimPrefix(typeName, "gadget_"), dst)
	}

	return false
}

var annotationsTemplates = map[string]map[string]string{
	"timestamp": {
		metadatav1.ColumnsWidthAnnotation:    "35",
		metadatav1.ColumnsMaxWidthAnnotation: "35",
		metadatav1.ColumnsEllipsisAnnotation: "end",
		metadatav1.ColumnsHiddenAnnotation:   "true",
		metadatav1.DescriptionAnnotation:     "Human-readable timestamp",
	},
	"node": {
		metadatav1.ColumnsWidthAnnotation:    "30",
		metadatav1.ColumnsEllipsisAnnotation: string(metadatav1.EllipsisMiddle),
	},
	"pod": {
		metadatav1.ColumnsWidthAnnotation:    "30",
		metadatav1.ColumnsEllipsisAnnotation: string(metadatav1.EllipsisMiddle),
	},
	"container": {
		metadatav1.ColumnsWidthAnnotation: "30",
	},
	"namespace": {
		metadatav1.ColumnsWidthAnnotation: "30",
	},
	"containerImageName": {
		metadatav1.ColumnsWidthAnnotation: "30",
	},
	"containerImageDigest": {
		metadatav1.ColumnsWidthAnnotation: "30",
	},
	"containerStartedAt": {
		metadatav1.ColumnsHiddenAnnotation: "true",
		metadatav1.ColumnsWidthAnnotation:  "35",
	},
	"comm": {
		metadatav1.DescriptionAnnotation:     "Process name",
		metadatav1.ColumnsMaxWidthAnnotation: "16",
	},
	"pcomm": {
		metadatav1.DescriptionAnnotation:     "Parent process name",
		metadatav1.ColumnsMaxWidthAnnotation: "16",
		metadatav1.ColumnsHiddenAnnotation:   "true",
	},
	"pid": {
		metadatav1.DescriptionAnnotation:      "Process ID",
		metadatav1.ColumnsMinWidthAnnotation:  "7",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"ppid": {
		metadatav1.DescriptionAnnotation:      "Parent Process ID",
		metadatav1.ColumnsMinWidthAnnotation:  "7",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
		metadatav1.ColumnsHiddenAnnotation:    "true",
	},
	"tid": {
		metadatav1.DescriptionAnnotation:      "Thread ID",
		metadatav1.ColumnsMinWidthAnnotation:  "7",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"uid": {
		metadatav1.DescriptionAnnotation:      "User ID",
		metadatav1.ColumnsMinWidthAnnotation:  "8",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"gid": {
		metadatav1.DescriptionAnnotation:      "Group ID",
		metadatav1.ColumnsMinWidthAnnotation:  "8",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"ns": {
		metadatav1.ColumnsHiddenAnnotation:    "true",
		metadatav1.ColumnsWidthAnnotation:     "12",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"mntns_id": {
		metadatav1.DescriptionAnnotation:      "Mount namespace ID",
		metadatav1.ColumnsHiddenAnnotation:    "true",
		metadatav1.ColumnsWidthAnnotation:     "12",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"netns_id": {
		metadatav1.DescriptionAnnotation:      "Network namespace ID",
		metadatav1.ColumnsHiddenAnnotation:    "true",
		metadatav1.ColumnsWidthAnnotation:     "12",
		metadatav1.ColumnsAlignmentAnnotation: string(metadatav1.AlignmentRight),
	},
	"l4endpoint": {
		metadatav1.ColumnsMinWidthAnnotation: "22",
		metadatav1.ColumnsWidthAnnotation:    "40",
		metadatav1.ColumnsMaxWidthAnnotation: "52",
	},
	"syscall": {
		metadatav1.ColumnsWidthAnnotation:    "18",
		metadatav1.ColumnsMaxWidthAnnotation: "28",
	},
	"errorString": {
		metadatav1.ColumnsWidthAnnotation: "12",
	},
}
