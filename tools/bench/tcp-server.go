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
	"bufio"
	"fmt"
	"log"
	"net"
	"runtime"
	"strings"
)

const (
	tcpListenAddr = "0.0.0.0:8080"
)

type tcpServer struct {
	listener net.Listener
}

func newTCPServer(_ string) (Generator, error) {
	return &tcpServer{}, nil
}

func (s *tcpServer) Start() error {
	listener, err := net.Listen("tcp", tcpListenAddr)
	if err != nil {
		return fmt.Errorf("binding to TCP %s: %w", tcpListenAddr, err)
	}

	s.listener = listener
	fmt.Printf("TCP server listening on %s with %d worker goroutines\n",
		tcpListenAddr, runtime.GOMAXPROCS(0))

	for range runtime.GOMAXPROCS(0) {
		go s.acceptConnections()
	}
	return nil
}

func (s *tcpServer) Stop() error {
	if s.listener != nil {
		return s.listener.Close()
	}
	return nil
}

func (s *tcpServer) acceptConnections() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("Accept error: %v", err)
			continue
		}

		go handleTCPConnection(conn)
	}
}

func handleTCPConnection(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		message := strings.TrimSpace(scanner.Text())

		// Respond to ping with pong
		if message == "Ping" {
			_, err := conn.Write([]byte("Pong\n"))
			if err != nil {
				log.Printf("Write error: %v", err)
				return
			}
		}
	}

	if err := scanner.Err(); err != nil {
		log.Printf("Scanner error: %v", err)
	}
}

func init() {
	// Register the TCP server generator
	registerGenerator("tcp-server", newTCPServer)
}
