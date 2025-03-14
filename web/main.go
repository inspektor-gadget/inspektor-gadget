// Copyright 2024-2025 The Inspektor Gadget authors
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

const (
	RunModeDefault = iota
	RunModeAttach
)

func main() {
	global := js.Global()
	global.Set("wrapWebSocket", js.FuncOf(wrapWebSocket))
	select {}
}

type DummyConn struct {
	w                     *KubeWebSocketWrapper
	channelID             uint8
	in                    chan []byte
	client                api.GadgetManagerClient
	instanceManagerClient api.GadgetInstanceManagerClient
	remainder             []byte
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

func (c *DummyConn) Run(successCb func(), errorCb func(string)) {
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
		if errorCb != nil {
			errorCb(err.Error())
		}
		return
	}
	c.client = api.NewGadgetManagerClient(conn)
	c.instanceManagerClient = api.NewGadgetInstanceManagerClient(conn)
	if successCb != nil {
		successCb()
	}
}

type KubeWebSocketWrapper struct {
	ws      js.Value
	conns   map[uint8]*DummyConn
	onError js.Value
	onReady js.Value
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

			go conn.Run(func() {
				if !w.onReady.IsUndefined() {
					w.onReady.Invoke()
				}
			}, func(err string) {
				if !w.onError.IsUndefined() {
					w.onError.Invoke(err)
				}
			})
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
		ws:      args[0],
		conns:   make(map[uint8]*DummyConn),
		onReady: args[1].Get("onReady"),
		onError: args[1].Get("onError"),
	}

	wrapper.Run()

	res := js.Global().Get("Object").New()

	jsjson := js.Global().Get("JSON")

	// first param should be the callback function to which the result is sent, second is an optional error handler
	res.Set("listGadgetInstances", js.FuncOf(func(this js.Value, args []js.Value) any {
		returnError := func(str string) {
			if len(args) > 1 {
				args[1].Invoke(str)
				return
			}
			fmt.Println(str)
		}

		_, ok := wrapper.conns[0]
		if !ok {
			returnError("connection not open")
			return false
		}

		go func() {
			instances, err := wrapper.conns[0].instanceManagerClient.ListGadgetInstances(context.Background(), &api.ListGadgetInstancesRequest{})
			if err != nil {
				returnError("listing gadget instances: " + err.Error())
				return
			}
			inst, _ := protojson.Marshal(instances)
			out := js.Global().Get("JSON").Call("parse", string(inst))
			args[0].Invoke(out.Get("gadgetInstances"))
		}()
		return nil
	}))

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

	res.Set("createGadgetInstance", js.FuncOf(func(this js.Value, args []js.Value) any {
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
		gadgetInstance := &api.GadgetInstance{}
		err := protojson.Unmarshal([]byte(req), gadgetInstance)
		if err != nil {
			returnError(err.Error())
			return false
		}

		go func() {
			res, err := wrapper.conns[0].instanceManagerClient.CreateGadgetInstance(context.Background(), &api.CreateGadgetInstanceRequest{
				GadgetInstance: gadgetInstance,
			})
			if err != nil {
				returnError(err.Error())
				return
			}
			j, _ := protojson.Marshal(res)
			args[1].Invoke(jsjson.Call("parse", string(j)))
		}()
		return true
	}))

	res.Set("deleteGadgetInstance", js.FuncOf(func(this js.Value, args []js.Value) any {
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

		id := args[0].String()

		go func() {
			res, err := wrapper.conns[0].instanceManagerClient.RemoveGadgetInstance(context.Background(), &api.GadgetInstanceId{
				Id: id,
			})
			if err != nil {
				returnError(err.Error())
			}
			j, _ := protojson.Marshal(res)
			args[1].Invoke(jsjson.Call("parse", string(j)))
		}()
		return true
	}))

	run := func(mode int) func(this js.Value, args []js.Value) any {
		return func(this js.Value, args []js.Value) any {
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

			onReady := args[1].Get("onReady")
			onDone := args[1].Get("onDone")
			onData := args[1].Get("onData")
			onGadgetInfo := args[1].Get("onGadgetInfo")

			cli, err := wrapper.conns[0].client.RunGadget(context.Background())
			if err != nil {
				returnError(err.Error())
				return false
			}
			go func() {
				var ctrl *api.GadgetControlRequest
				req := js.Global().Get("JSON").Call("stringify", args[0]).String()
				switch mode {
				case RunModeDefault:
					runRequest := &api.GadgetRunRequest{}
					err := protojson.Unmarshal([]byte(req), runRequest)
					if err != nil {
						returnError(err.Error())
						return
					}
					ctrl = &api.GadgetControlRequest{Event: &api.GadgetControlRequest_RunRequest{RunRequest: runRequest}}
				case RunModeAttach:
					attachRequest := &api.GadgetAttachRequest{}
					err := protojson.Unmarshal([]byte(req), attachRequest)
					if err != nil {
						returnError(err.Error())
						return
					}
					ctrl = &api.GadgetControlRequest{Event: &api.GadgetControlRequest_AttachRequest{AttachRequest: attachRequest}}
				default:
					return
				}

				err = cli.Send(ctrl)
				if err != nil {
					returnError(err.Error())
					return
				}

				datasources := make(map[uint32]datasource.DataSource)
				jsonFormatters := make(map[uint32]*json.Formatter)

				if !onReady.IsUndefined() {
					onReady.Invoke()
				}

				for {
					ev, err := cli.Recv()
					if err != nil {
						if errors.Is(err, io.EOF) {
							if !onDone.IsUndefined() {
								onDone.Invoke()
							}
							return
						}
						fmt.Println(err.Error())
						if !onDone.IsUndefined() {
							onDone.Invoke()
						}
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
		}
	}

	// first param to runGadget is the GadgetRunRequest, second an object with callback definitions
	res.Set("runGadget", js.FuncOf(run(RunModeDefault)))
	res.Set("attachGadgetInstance", js.FuncOf(run(RunModeAttach)))
	return res
}
