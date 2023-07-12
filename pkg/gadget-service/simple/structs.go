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

package simple

import "encoding/json"

type GadgetEvent struct {
	ID      string          `json:"id"`
	Type    uint32          `json:"type,omitempty"`
	Payload json.RawMessage `json:"payload"`
}

type ID struct {
	ID string `json:"id"`
}

type Command struct {
	ID      string          `json:"id"`
	Action  string          `json:"action"`
	Payload json.RawMessage `json:"payload"`
}

type GadgetStartRequest struct {
	ID             string            `json:"id"`
	GadgetName     string            `json:"gadgetName"`
	GadgetCategory string            `json:"gadgetCategory"`
	Params         map[string]string `json:"params"`
	Timeout        int               `json:"timeout"`
	LogLevel       int               `json:"logLevel"`
}

type GadgetStopRequest struct {
	ID string `json:"id"`
}
