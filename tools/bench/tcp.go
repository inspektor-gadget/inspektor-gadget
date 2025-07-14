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

package main

import (
	"fmt"
	"net"
	"strings"
	"time"
)

type tcpClientGenerator struct {
	baseGenerator
}

type tcpClientConf struct {
	server string
	maxRPS int
}

func newTCPClient(confStr string) (Generator, error) {
	conf, err := parseTCPConfStr(confStr)
	if err != nil {
		return nil, fmt.Errorf("parsing TCP client config: %w", err)
	}

	cb := func() error {
		conn, err := net.DialTimeout("tcp", conf.server, 5*time.Second)
		if err != nil {
			return err
		}
		defer conn.Close()

		// Send a simple message to the server
		_, err = conn.Write([]byte("Ping\n"))
		if err != nil {
			return err
		}

		// Optional: read response
		buffer := make([]byte, 1024)
		_, err = conn.Read(buffer)
		return err
	}

	g := &tcpClientGenerator{
		baseGenerator: NewBaseGen(cb),
	}

	return g, nil
}

func parseTCPConfStr(confStr string) (*tcpClientConf, error) {
	tcpConf := tcpClientConf{
		maxRPS: eventsPerSecond,
	}

	parts := strings.Split(confStr, ";")

	for _, part := range parts {
		confParts := strings.SplitN(part, "=", 2)
		confName := confParts[0]
		confVal := confParts[1]

		switch confName {
		case "server":
			tcpConf.server = confVal
		default:
			return nil, fmt.Errorf("unknown TCP client config: %s", confName)
		}
	}

	return &tcpConf, nil
}

func init() {
	registerGenerator("tcp", newTCPClient)
}
