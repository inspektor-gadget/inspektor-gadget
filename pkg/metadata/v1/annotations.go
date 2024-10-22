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

package metadatav1

const (
	ColumnsWidthAnnotation     = "columns.width"
	ColumnsMaxWidthAnnotation  = "columns.maxwidth"
	ColumnsMinWidthAnnotation  = "columns.minwidth"
	ColumnsAlignmentAnnotation = "columns.alignment"
	ColumnsEllipsisAnnotation  = "columns.ellipsis"
	ColumnsHiddenAnnotation    = "columns.hidden"
	ColumnsFixedAnnotation     = "columns.fixed"
	ColumnsHexAnnotation       = "columns.hex"

	DescriptionAnnotation = "description"
	TemplateAnnotation    = "template"
)

var AnnotationsTemplates = map[string]map[string]string{
	"timestamp": {
		ColumnsWidthAnnotation:    "35",
		ColumnsMaxWidthAnnotation: "35",
		ColumnsEllipsisAnnotation: "end",
		ColumnsHiddenAnnotation:   "true",
		DescriptionAnnotation:     "Microseconds since Unix epoch",
	},
	"node": {
		ColumnsWidthAnnotation:    "30",
		ColumnsEllipsisAnnotation: string(EllipsisMiddle),
	},
	"pod": {
		ColumnsWidthAnnotation:    "30",
		ColumnsEllipsisAnnotation: string(EllipsisMiddle),
	},
	"container": {
		ColumnsWidthAnnotation: "30",
	},
	"namespace": {
		ColumnsWidthAnnotation: "30",
	},
	"containerImageName": {
		ColumnsWidthAnnotation: "30",
	},
	"containerImageDigest": {
		ColumnsWidthAnnotation: "30",
	},
	"containerStartedAt": {
		ColumnsHiddenAnnotation: "true",
		ColumnsWidthAnnotation:  "35",
	},
	"comm": {
		DescriptionAnnotation:     "Process name",
		ColumnsMaxWidthAnnotation: "16",
	},
	"pcomm": {
		DescriptionAnnotation:     "Parent process name",
		ColumnsMaxWidthAnnotation: "16",
		ColumnsHiddenAnnotation:   "true",
	},
	"pid": {
		DescriptionAnnotation:      "Process ID",
		ColumnsMinWidthAnnotation:  "7",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"ppid": {
		DescriptionAnnotation:      "Parent process ID",
		ColumnsMinWidthAnnotation:  "7",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
		ColumnsHiddenAnnotation:    "true",
	},
	"tid": {
		DescriptionAnnotation:      "Thread ID",
		ColumnsMinWidthAnnotation:  "7",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"uid": {
		DescriptionAnnotation:      "User ID",
		ColumnsMinWidthAnnotation:  "8",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"gid": {
		DescriptionAnnotation:      "Group ID",
		ColumnsMinWidthAnnotation:  "8",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"ns": {
		ColumnsHiddenAnnotation:    "true",
		ColumnsWidthAnnotation:     "12",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"mntns_id": {
		DescriptionAnnotation:      "Mount namespace ID",
		ColumnsHiddenAnnotation:    "true",
		ColumnsWidthAnnotation:     "12",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"netns_id": {
		DescriptionAnnotation:      "Network namespace ID",
		ColumnsHiddenAnnotation:    "true",
		ColumnsWidthAnnotation:     "12",
		ColumnsAlignmentAnnotation: string(AlignmentRight),
	},
	"l4endpoint": {
		ColumnsMinWidthAnnotation: "22",
		ColumnsWidthAnnotation:    "40",
		ColumnsMaxWidthAnnotation: "52",
	},
	"syscall": {
		ColumnsWidthAnnotation:    "18",
		ColumnsMaxWidthAnnotation: "28",
	},
	"errorString": {
		ColumnsWidthAnnotation: "12",
	},
}

func ApplyAnnotationsTemplate(templateAnn string, dst map[string]string) bool {
	template, ok := AnnotationsTemplates[templateAnn]
	for k, v := range template {
		dst[k] = v
	}
	return ok
}
