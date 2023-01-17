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

package gadgets

const (
	CategoryAdvise   = "advise"
	CategoryAudit    = "audit"
	CategoryProfile  = "profile"
	CategorySnapshot = "snapshot"
	CategoryTop      = "top"
	CategoryTrace    = "trace"
	CategoryOther    = "other"
)

var categories = map[string]string{
	CategoryAdvise:   "Recommend system configurations based on collected information",
	CategoryAudit:    "Audit a subsystem",
	CategoryProfile:  "Profile different subsystems",
	CategorySnapshot: "Take a snapshot of a subsystem and print it",
	CategoryTop:      "Gather, sort and periodically report events according to a given criteria",
	CategoryTrace:    "Trace and print system events",
	CategoryOther:    "Other Gadgets",
}

// GetCategories returns a map of category name to category description
func GetCategories() map[string]string {
	return categories
}
