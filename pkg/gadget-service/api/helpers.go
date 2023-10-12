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

package api

import (
	"fmt"
	"net/url"
)

func ParseSocketAddress(addr string) (string, string, error) {
	socketURL, err := url.Parse(addr)
	if err != nil {
		return "", "", fmt.Errorf("invalid socket address %q: %w", addr, err)
	}
	var socketPath string
	socketType := socketURL.Scheme
	switch socketType {
	default:
		return "", "", fmt.Errorf("invalid type %q for socket; please use 'unix' or 'tcp'", socketType)
	case "unix":
		socketPath = socketURL.Path
	case "tcp":
		socketPath = socketURL.Host
	}
	return socketType, socketPath, nil
}
