// Copyright 2019-2022 The Inspektor Gadget authors
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

type Data struct {
	Count         uint64 `json:"count"`
	IntervalStart uint64 `json:"interval-start"`
	IntervalEnd   uint64 `json:"interval-end,omitempty"`
}

type Report struct {
	ValType string `json:"val_type,omitempty"`
	Data    []Data `json:"data,omitempty"`
	Time    string `json:"ts,omitempty"`
}
