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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall/js"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/datasource/formatters/json"
	"github.com/inspektor-gadget/inspektor-gadget/pkg/gadget-service/api"
)

func main() {
	global := js.Global()
	global.Set("wrapWebSocket", js.FuncOf(wrapWebSocket))
	select {}
}

type DummyConn struct {
	w         *KubeWebSocketWrapper
	channelID uint8
	in        chan []byte
	client    api.GadgetManagerClient
	remainder []byte
}

func (c *DummyConn) Read(b []byte) (n int, err error) {
	if c.remainder != nil {
		n = copy(b, c.remainder)
		c.remainder = c.remainder[n:]
		if len(c.remainder) == 0 {
			c.remainder = nil
		}
		return n, nil
	}
	buf := <-c.in
	if buf == nil {
		return 0, io.EOF
	}
	n = copy(b, buf)
	if n < len(buf) {
		c.remainder = buf[n:]
	}
	return len(buf), nil
}

func (c *DummyConn) Write(b []byte) (n int, err error) {
	// create new buffer
	arrayBuffer := js.Global().Get("ArrayBuffer").New(len(b) + 1)
	arrayView := js.Global().Get("Uint8Array").New(arrayBuffer)
	js.CopyBytesToJS(arrayView, append([]byte{c.channelID}, b...))
	c.w.ws.Call("send", arrayBuffer)
	return len(b), nil
}

func (c *DummyConn) Close() error {
	return nil
}

func (c *DummyConn) LocalAddr() net.Addr {
	return &net.IPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Zone: "",
	}
}

func (c *DummyConn) RemoteAddr() net.Addr {
	return &net.IPAddr{
		IP:   net.IPv4(127, 0, 0, 1),
		Zone: "",
	}
}

func (c *DummyConn) SetDeadline(t time.Time) error {
	return nil
}

func (c *DummyConn) SetReadDeadline(t time.Time) error {
	return nil
}

func (c *DummyConn) SetWriteDeadline(t time.Time) error {
	return nil
}

func (c *DummyConn) Run() {
	if c.channelID%2 != 0 {
		return
	}
	conn, err := grpc.NewClient("passthrough:///whoops",
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, s string) (net.Conn, error) {
			return c, nil
		}),
	)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	c.client = api.NewGadgetManagerClient(conn)
}

type KubeWebSocketWrapper struct {
	ws    js.Value
	conns map[uint8]*DummyConn
}

func (w *KubeWebSocketWrapper) Run() {
	w.ws.Set("binaryType", "arraybuffer")
	onOpen := js.FuncOf(func(this js.Value, args []js.Value) any {
		return nil
	})
	onMessage := js.FuncOf(func(this js.Value, args []js.Value) any {
		arrayView := js.Global().Get("Uint8Array").New(args[0].Get("data"))
		buf := make([]byte, arrayView.Get("length").Int())
		js.CopyBytesToGo(buf, arrayView)

		channelID := buf[0]
		conn, ok := w.conns[channelID]
		if !ok {
			// create new channel
			conn = &DummyConn{
				w:         w,
				channelID: channelID,
				in:        make(chan []byte, 64),
			}
			w.conns[channelID] = conn
			conn.in <- buf[3:] // skip first three bytes

			go conn.Run()
			return nil
		}

		conn.in <- buf[1:] // skip first byte
		return nil
	})
	w.ws.Call("addEventListener", "open", onOpen)
	w.ws.Call("addEventListener", "message", onMessage)
}

func wrapWebSocket(this js.Value, args []js.Value) interface{} {
	if len(args) != 2 {
		return "invalid arguments"
	}

	wrapper := &KubeWebSocketWrapper{
		ws:    args[0],
		conns: make(map[uint8]*DummyConn),
	}
	wrapper.Run()

	res := js.Global().Get("Object").New()

	// first param to getGadgetInfo is the GetGadgetInfoRequest, second the callback to which the result is sent
	// and third is an optional callback that is called with an error
	res.Set("getGadgetInfo", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			fmt.Println("expected at least two arguments")
			return false
		}

		returnError := func(str string) {
			if len(args) > 2 {
				args[2].Invoke(str)
				return
			}
			fmt.Println(str)
		}

		_, ok := wrapper.conns[0]
		if !ok {
			returnError("connection not open")
			return false
		}
		req := js.Global().Get("JSON").Call("stringify", args[0]).String()
		gadgetInfoRequest := &api.GetGadgetInfoRequest{}
		err := protojson.Unmarshal([]byte(req), gadgetInfoRequest)
		if err != nil {
			returnError(err.Error())
			return false
		}
		go func() {
			gi, err := wrapper.conns[0].client.GetGadgetInfo(context.Background(), gadgetInfoRequest)
			if err != nil {
				returnError(err.Error())
				return
			}
			d, _ := protojson.Marshal(gi.GadgetInfo)
			out := js.Global().Get("JSON").Call("parse", string(d))
			args[1].Invoke(out)
			return
		}()
		return true
	}))

	// first param to runGadget is the GadgetRunRequest, second an object with callback definitions
	res.Set("runGadget", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) < 2 {
			fmt.Println("expected at least two arguments")
			return false
		}

		returnError := func(str string) {
			if len(args) > 2 {
				args[2].Invoke(str)
				return
			}
			fmt.Println(str)
		}

		_, ok := wrapper.conns[0]
		if !ok {
			returnError("connection not open")
			return false
		}

		onData := args[1].Get("onData")
		onGadgetInfo := args[1].Get("onGadgetInfo")

		req := js.Global().Get("JSON").Call("stringify", args[0]).String()
		runRequest := &api.GadgetRunRequest{}
		err := protojson.Unmarshal([]byte(req), runRequest)
		if err != nil {
			returnError(err.Error())
			return false
		}
		cli, err := wrapper.conns[0].client.RunGadget(context.Background())
		if err != nil {
			returnError(err.Error())
			return false
		}
		go func() {
			err = cli.Send(&api.GadgetControlRequest{Event: &api.GadgetControlRequest_RunRequest{RunRequest: runRequest}})
			if err != nil {
				returnError(err.Error())
				return
			}

			datasources := make(map[uint32]datasource.DataSource)
			jsonFormatters := make(map[uint32]*json.Formatter)

			jsjson := js.Global().Get("JSON")
			for {
				ev, err := cli.Recv()
				if err != nil {
					if errors.Is(err, io.EOF) {
						return
					}
					fmt.Println(err.Error())
					break
				}
				switch ev.Type {
				case api.EventTypeGadgetPayload:
					if onData.IsUndefined() {
						continue
					}
					ds := datasources[ev.DataSourceID]
					switch ds.Type() {
					case datasource.TypeSingle:
						p, err := ds.NewPacketSingleFromRaw(ev.Payload)
						if err != nil {
							returnError(err.Error())
							return
						}
						onData.Invoke(ev.DataSourceID, jsjson.Call("parse", string(jsonFormatters[ev.DataSourceID].Marshal(p))))
						ds.Release(p)
					case datasource.TypeArray:
						p, err := ds.NewPacketArrayFromRaw(ev.Payload)
						if err != nil {
							returnError(err.Error())
							return
						}
						onData.Invoke(ev.DataSourceID, jsjson.Call("parse", string(jsonFormatters[ev.DataSourceID].MarshalArray(p))))
						ds.Release(p)
					}
				case api.EventTypeGadgetInfo:
					gi := &api.GadgetInfo{}
					err = proto.Unmarshal(ev.Payload, gi)
					if err != nil {
						returnError(err.Error())
						return
					}
					for _, ds := range gi.DataSources {
						nds, err := datasource.NewFromAPI(ds)
						if err != nil {
							returnError(err.Error())
							return
						}
						datasources[ds.Id] = nds
						jsonFormatters[ds.Id], err = json.New(nds, json.WithPretty(true, "  "))
						if err != nil {
							returnError(err.Error())
							return
						}
					}
					if !onGadgetInfo.IsUndefined() {
						d, _ := protojson.Marshal(gi)
						onGadgetInfo.Invoke(jsjson.Call("parse", (string(d))))
					}
				}
			}
			return
		}()

		ctrl := js.Global().Get("Object").New()
		ctrl.Set("stop", js.FuncOf(func(this js.Value, args []js.Value) any {
			err = cli.Send(&api.GadgetControlRequest{Event: &api.GadgetControlRequest_StopRequest{}})
			if err != nil {
				returnError(err.Error())
				return nil
			}
			return nil
		}))

		return ctrl
	}))
	return res
}
