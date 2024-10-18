// Copyright 2023-2024 The Inspektor Gadget authors
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

package common

import (
	"fmt"
	"net"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
)

func GetIPForVersion(data datasource.Data, version, ipAddr datasource.FieldAccessor) (string, error) {
	ip := ipAddr.Get(data)
	if ip == nil {
		return "", fmt.Errorf("IP field not found")
	}

	v, err := version.Uint8(data)
	if err != nil {
		return "", fmt.Errorf("getting version: %w", err)
	}

	var ipStr string
	switch v {
	case 4:
		ipStr, err = net.IP(ip[:4]).String(), nil
	case 6:
		ipStr, err = net.IP(ip).String(), nil
	default:
		err = fmt.Errorf("unknown IP version: %d", v)
	}
	if err != nil {
		return "", fmt.Errorf("getting IP: %w", err)
	}

	return ipStr, nil
}
