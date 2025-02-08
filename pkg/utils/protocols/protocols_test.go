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
package protocols

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetProtocolNameByNumber(t *testing.T) {
	protocols := []struct {
		description string
		number      int
		name        string
		ok          bool
	}{
		{
			description: "TCP was found",
			number:      6,
			name:        "TCP",
			ok:          true,
		},
		{
			description: "SCTP was found",
			number:      132,
			name:        "SCTP",
			ok:          true,
		},
		{
			description: "number was not found",
			number:      999,
			name:        "",
			ok:          false,
		},
		{
			description: "number was not found",
			number:      -1,
			name:        "",
			ok:          false,
		},
	}

	for _, protocol := range protocols {
		t.Run(protocol.description, func(t *testing.T) {
			name, ok := GetProtocolNameByNumber(protocol.number)
			assert.Equal(t, protocol.name, name)
			assert.Equal(t, protocol.ok, ok)
		})
	}
}
