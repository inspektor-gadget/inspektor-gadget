// Copyright 2026 The Inspektor Gadget authors
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
	_ "embed"
	"fmt"
	"strings"

	"google.golang.org/protobuf/encoding/protowire"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"

	api "github.com/inspektor-gadget/inspektor-gadget/wasmapi/go"
)

const (
	newClientStreamSymbol = "google.golang.org/grpc.newClientStream"
	sendMsgSymbol         = "google.golang.org/grpc.(*csAttempt).sendMsg"
)

var payload []byte

//go:wasmexport gadgetPreStart
func gadgetPreStart() int32 {
	// Check if user specified a target via "pid" or "path" parameters.
	// If set, override the default attach_to compiled into the SEC() names.
	pid, _ := api.GetParamValue("target-pid", 32)
	path, _ := api.GetParamValue("target-path", 512)

	var target string
	switch {
	case pid != "":
		target = fmt.Sprintf("/proc/%s/exe", pid)
	case path != "":
		target = path
	default:
		return 0
	}

	api.Infof("Overriding attach_to with target=%s", target)
	api.SetConfig("programs.uprobe_new_client_stream.attach_to",
		target+":"+newClientStreamSymbol)
	api.SetConfig("programs.uprobe_cs_attempt_send_msg.attach_to",
		target+":"+sendMsgSymbol)
	return 0
}

//go:wasmexport gadgetInit
func gadgetInit() int32 {
	// Initialize proto registry based on --proto parameter
	protoMode, _ := api.GetParamValue("proto", 64)
	switch protoMode {
	case "cri":
		if err := initProtoRegistry(criDescriptorBytes); err != nil {
			api.Warnf("failed to init CRI proto registry: %s", err)
			return 1
		}
		api.Infof("Proto-aware decoding enabled: CRI (runtime.v1)")
	case "containerd":
		if err := initProtoRegistry(containerdDescriptorBytes); err != nil {
			api.Warnf("failed to init containerd proto registry: %s", err)
			return 1
		}
		api.Infof("Proto-aware decoding enabled: containerd")
	case "none", "":
		// Schema-less mode (default)
	default:
		api.Warnf("unknown proto mode: %s (use none, cri, or containerd)", protoMode)
		return 1
	}

	ds, err := api.GetDataSource("grpc")
	if err != nil {
		api.Warnf("failed to get datasource: %s", err)
		return 1
	}

	methodF, err := ds.GetField("method")
	if err != nil {
		api.Warnf("failed to get method field: %s", err)
		return 1
	}

	typeRawF, err := ds.GetField("type_raw")
	if err != nil {
		api.Warnf("failed to get type_raw field: %s", err)
		return 1
	}

	compressedF, err := ds.GetField("compressed")
	if err != nil {
		api.Warnf("failed to get compressed field: %s", err)
		return 1
	}

	capturedLenF, err := ds.GetField("captured_len")
	if err != nil {
		api.Warnf("failed to get captured_len field: %s", err)
		return 1
	}

	payloadF, err := ds.GetField("payload")
	if err != nil {
		api.Warnf("failed to get payload field: %s", err)
		return 1
	}

	serviceF, err := ds.AddField("service", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add service field: %s", err)
		return 1
	}

	rpcMethodF, err := ds.AddField("rpc_method", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add rpc_method field: %s", err)
		return 1
	}

	decodedPayloadF, err := ds.AddField("decoded_payload", api.Kind_String)
	if err != nil {
		api.Warnf("failed to add decoded_payload field: %s", err)
		return 1
	}

	payload = make([]byte, 4096)

	ds.Subscribe(func(source api.DataSource, data api.Data) {
		// Parse method into service + rpc_method
		method, err := methodF.String(data, 256)
		if err == nil && method != "" {
			service, rpcMethod := parseMethod(method)
			serviceF.SetString(data, service)
			rpcMethodF.SetString(data, rpcMethod)
		}

		// Only decode payload for send events (type_raw == 1)
		typeRaw, err := typeRawF.Uint32(data)
		if err != nil || typeRaw != 1 {
			return
		}

		// Skip compressed payloads (we can't decompress in WASM)
		compressed, err := compressedF.Uint8(data)
		if err != nil || compressed != 0 {
			return
		}

		capturedLen, err := capturedLenF.Uint32(data)
		if err != nil || capturedLen == 0 {
			return
		}

		n, err := payloadF.Bytes(data, payload)
		if err != nil || n == 0 {
			return
		}

		var decoded string
		if activeRegistry != nil {
			decoded = decodeWithSchema(method, payload[:n])
		}
		if decoded == "" {
			decoded = decodeProtobufWireFormat(payload[:n])
		}
		if decoded != "" {
			decodedPayloadF.SetString(data, decoded)
		}
	}, 0)

	return 0
}

// parseMethod splits "/package.Service/Method" into ("package.Service", "Method")
func parseMethod(method string) (string, string) {
	// gRPC methods follow the format: /service/method
	if !strings.HasPrefix(method, "/") {
		return method, ""
	}
	parts := strings.SplitN(method[1:], "/", 2)
	if len(parts) != 2 {
		return method, ""
	}
	return parts[0], parts[1]
}

// decodeProtobufWireFormat performs schema-less protobuf wire format decoding.
// Returns a human-readable string of field_number:type(value) pairs.
func decodeProtobufWireFormat(b []byte) string {
	if len(b) == 0 {
		return ""
	}

	var fields []string
	for len(b) > 0 {
		num, wtype, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]

		switch wtype {
		case protowire.VarintType:
			v, n := protowire.ConsumeVarint(b)
			if n < 0 {
				break
			}
			b = b[n:]
			fields = append(fields, fmt.Sprintf("%d:varint(%d)", num, v))

		case protowire.Fixed32Type:
			v, n := protowire.ConsumeFixed32(b)
			if n < 0 {
				break
			}
			b = b[n:]
			fields = append(fields, fmt.Sprintf("%d:fixed32(%d)", num, v))

		case protowire.Fixed64Type:
			v, n := protowire.ConsumeFixed64(b)
			if n < 0 {
				break
			}
			b = b[n:]
			fields = append(fields, fmt.Sprintf("%d:fixed64(%d)", num, v))

		case protowire.BytesType:
			v, n := protowire.ConsumeBytes(b)
			if n < 0 {
				break
			}
			b = b[n:]
			// Try to decode as nested message first
			if nested := decodeProtobufWireFormat(v); nested != "" && isLikelyMessage(v) {
				fields = append(fields, fmt.Sprintf("%d:{%s}", num, nested))
			} else {
				// Treat as string if printable, otherwise hex
				if isPrintable(v) {
					fields = append(fields, fmt.Sprintf("%d:string(%q)", num, string(v)))
				} else {
					fields = append(fields, fmt.Sprintf("%d:bytes(%x)", num, v))
				}
			}

		case protowire.StartGroupType:
			// Skip groups (deprecated)
			_, n := protowire.ConsumeGroup(num, b)
			if n < 0 {
				break
			}
			b = b[n:]
			fields = append(fields, fmt.Sprintf("%d:group(...)", num))

		default:
			// Unknown wire type, stop
			return strings.Join(fields, ", ")
		}
	}

	return strings.Join(fields, ", ")
}

// isLikelyMessage checks if bytes look like a valid protobuf message
// by verifying that parsing consumed all bytes without errors.
func isLikelyMessage(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	remaining := b
	fieldCount := 0
	for len(remaining) > 0 {
		num, wtype, n := protowire.ConsumeTag(remaining)
		if n < 0 || num == 0 {
			return false
		}
		remaining = remaining[n:]

		switch wtype {
		case protowire.VarintType:
			_, n = protowire.ConsumeVarint(remaining)
		case protowire.Fixed32Type:
			_, n = protowire.ConsumeFixed32(remaining)
		case protowire.Fixed64Type:
			_, n = protowire.ConsumeFixed64(remaining)
		case protowire.BytesType:
			_, n = protowire.ConsumeBytes(remaining)
		case protowire.StartGroupType:
			_, n = protowire.ConsumeGroup(num, remaining)
		default:
			return false
		}
		if n < 0 {
			return false
		}
		remaining = remaining[n:]
		fieldCount++
	}
	return fieldCount > 0
}

// isPrintable checks if all bytes are printable ASCII/UTF-8
func isPrintable(b []byte) bool {
	for _, c := range b {
		if c < 0x20 || c > 0x7e {
			return false
		}
	}
	return len(b) > 0
}

func main() {}

// --- Proto-aware decoding ---

//go:embed proto/cri.pb
var criDescriptorBytes []byte

//go:embed proto/containerd.pb
var containerdDescriptorBytes []byte

// protoRegistry holds parsed message descriptors.
type protoRegistry struct {
	messages map[string]protoreflect.MessageDescriptor
	// methods maps "/package.Service/Method" → request message full name
	methods map[string]string
}

var activeRegistry *protoRegistry

func initProtoRegistry(descriptorBytes []byte) error {
	fds := &descriptorpb.FileDescriptorSet{}
	if err := proto.Unmarshal(descriptorBytes, fds); err != nil {
		return fmt.Errorf("unmarshaling FileDescriptorSet: %w", err)
	}

	files, err := protodesc.NewFiles(fds)
	if err != nil {
		return fmt.Errorf("creating file registry: %w", err)
	}

	reg := &protoRegistry{
		messages: make(map[string]protoreflect.MessageDescriptor),
		methods:  make(map[string]string),
	}

	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		collectMessages(reg, fd.Messages())
		collectServices(reg, fd.Services())
		return true
	})

	activeRegistry = reg
	return nil
}

func collectMessages(reg *protoRegistry, msgs protoreflect.MessageDescriptors) {
	for i := 0; i < msgs.Len(); i++ {
		msg := msgs.Get(i)
		reg.messages[string(msg.FullName())] = msg
		collectMessages(reg, msg.Messages())
	}
}

func collectServices(reg *protoRegistry, svcs protoreflect.ServiceDescriptors) {
	for i := 0; i < svcs.Len(); i++ {
		svc := svcs.Get(i)
		methods := svc.Methods()
		for j := 0; j < methods.Len(); j++ {
			m := methods.Get(j)
			path := fmt.Sprintf("/%s/%s", svc.FullName(), m.Name())
			reg.methods[path] = string(m.Input().FullName())
		}
	}
}

// decodeWithSchema decodes protobuf bytes using the active registry.
func decodeWithSchema(method string, b []byte) string {
	if activeRegistry == nil {
		return ""
	}

	msgName, ok := activeRegistry.methods[method]
	if !ok {
		return ""
	}

	msgDesc, ok := activeRegistry.messages[msgName]
	if !ok {
		return ""
	}

	return decodeMessageWithSchema(msgDesc, b)
}

func decodeMessageWithSchema(desc protoreflect.MessageDescriptor, b []byte) string {
	if len(b) == 0 {
		return ""
	}

	var fields []string
	for len(b) > 0 {
		num, wtype, n := protowire.ConsumeTag(b)
		if n < 0 {
			break
		}
		b = b[n:]

		fd := desc.Fields().ByNumber(protoreflect.FieldNumber(num))
		fieldName := fmt.Sprintf("%d", num)
		if fd != nil {
			fieldName = string(fd.Name())
		}

		switch wtype {
		case protowire.VarintType:
			v, vn := protowire.ConsumeVarint(b)
			if vn < 0 {
				return strings.Join(fields, ", ")
			}
			b = b[vn:]
			fields = append(fields, formatVarint(fd, fieldName, v))

		case protowire.Fixed32Type:
			v, vn := protowire.ConsumeFixed32(b)
			if vn < 0 {
				return strings.Join(fields, ", ")
			}
			b = b[vn:]
			fields = append(fields, fmt.Sprintf("%s:%d", fieldName, v))

		case protowire.Fixed64Type:
			v, vn := protowire.ConsumeFixed64(b)
			if vn < 0 {
				return strings.Join(fields, ", ")
			}
			b = b[vn:]
			fields = append(fields, fmt.Sprintf("%s:%d", fieldName, v))

		case protowire.BytesType:
			v, vn := protowire.ConsumeBytes(b)
			if vn < 0 {
				return strings.Join(fields, ", ")
			}
			b = b[vn:]
			fields = append(fields, formatBytesWithSchema(fd, fieldName, v))

		case protowire.StartGroupType:
			_, vn := protowire.ConsumeGroup(num, b)
			if vn < 0 {
				return strings.Join(fields, ", ")
			}
			b = b[vn:]
			fields = append(fields, fmt.Sprintf("%s:{...}", fieldName))

		default:
			return strings.Join(fields, ", ")
		}
	}

	return strings.Join(fields, ", ")
}

func formatVarint(fd protoreflect.FieldDescriptor, name string, v uint64) string {
	if fd == nil {
		return fmt.Sprintf("%s:%d", name, v)
	}

	switch fd.Kind() {
	case protoreflect.BoolKind:
		if v == 0 {
			return fmt.Sprintf("%s:false", name)
		}
		return fmt.Sprintf("%s:true", name)
	case protoreflect.EnumKind:
		enumDesc := fd.Enum()
		if enumDesc != nil {
			val := enumDesc.Values().ByNumber(protoreflect.EnumNumber(v))
			if val != nil {
				return fmt.Sprintf("%s:%s", name, val.Name())
			}
		}
		return fmt.Sprintf("%s:%d", name, v)
	case protoreflect.Sint32Kind, protoreflect.Sint64Kind:
		return fmt.Sprintf("%s:%d", name, protowire.DecodeZigZag(v))
	default:
		return fmt.Sprintf("%s:%d", name, v)
	}
}

func formatBytesWithSchema(fd protoreflect.FieldDescriptor, name string, v []byte) string {
	if fd != nil && fd.Kind() == protoreflect.MessageKind {
		subDesc := fd.Message()
		if subDesc != nil {
			nested := decodeMessageWithSchema(subDesc, v)
			if nested != "" {
				return fmt.Sprintf("%s:{%s}", name, nested)
			}
		}
	}

	if fd != nil && fd.Kind() == protoreflect.StringKind {
		return fmt.Sprintf("%s:%q", name, string(v))
	}

	if fd != nil && fd.IsMap() {
		subDesc := fd.Message()
		if subDesc != nil {
			nested := decodeMessageWithSchema(subDesc, v)
			if nested != "" {
				return fmt.Sprintf("%s:{%s}", name, nested)
			}
		}
	}

	if isPrintable(v) {
		return fmt.Sprintf("%s:%q", name, string(v))
	}
	return fmt.Sprintf("%s:bytes(%x)", name, v)
}
