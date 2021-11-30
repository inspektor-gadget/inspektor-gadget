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

package types

import (
	eventtypes "github.com/kinvolk/inspektor-gadget/pkg/types"
)

type Event struct {
	eventtypes.Event

	InterfaceNameIn   string `json:"interface_name_in,omitempty"`
	InterfaceNameOut  string `json:"interface_name_out,omitempty"`
	InterfaceIndexIn  int    `json:"interface_index_in,omitempty"`
	InterfaceIndexOut int    `json:"interface_index_out,omitempty"`
	NetnsIn           uint64 `json:"netns_in,omitempty"`
	NetnsOut          uint64 `json:"netns_out,omitempty"`
	TableName         string `json:"table_name,omitempty"`
	ChainName         string `json:"chain_name,omitempty"`
	Comment           string `json:"comment,omitempty"`
	RuleNum           int    `json:"rule_num,omitempty"`
	Rule              string `json:"rule,omitempty"`
	Rules             string `json:"rules,omitempty"`
}
