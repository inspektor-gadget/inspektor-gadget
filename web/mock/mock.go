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

package main

import (
	"net"
	"net/http"
	"os"

	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{} // use default options

func runProxy() {
	mux := http.NewServeMux()
	mux.HandleFunc("/grpc", func(w http.ResponseWriter, r *http.Request) {
		c, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return
		}
		defer c.Close()

		addr := "10.211.55.12:7777"
		if len(os.Args) > 1 {
			addr = os.Args[1]
		}

		// connect
		xc, err := net.Dial("tcp", addr)
		if err != nil {
			return
		}
		defer xc.Close()

		c.WriteMessage(websocket.BinaryMessage, []byte{0x00, 80, 0})

		go func() {
			for {
				b := make([]byte, 1024)
				l, err := xc.Read(b)
				if err != nil {
					xc.Close()
					return
				}
				err = c.WriteMessage(websocket.BinaryMessage, append([]byte{0x00}, b[:l]...))
				if err != nil {
					xc.Close()
					return
				}
			}
		}()

		for {
			_, b, err := c.ReadMessage()
			if err != nil {
				return
			}
			_, err = xc.Write(b[1:])
			if err != nil {
				return
			}
		}
	})
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("./static"))))
	go http.ListenAndServe(":8080", mux)
}

func main() {
	runProxy()
	select {}
}
