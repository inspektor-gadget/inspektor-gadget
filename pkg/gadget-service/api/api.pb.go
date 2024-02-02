// Code generated by protoc-gen-go. DO NOT EDIT.
// source: api/api.proto

package api

import (
	fmt "fmt"
	proto "github.com/golang/protobuf/proto"
	math "math"
)

// Reference imports to suppress errors if they are not otherwise used.
var _ = proto.Marshal
var _ = fmt.Errorf
var _ = math.Inf

// This is a compile-time assertion to ensure that this generated file
// is compatible with the proto package it is being compiled against.
// A compilation error at this line likely means your copy of the
// proto package needs to be updated.
const _ = proto.ProtoPackageIsVersion3 // please upgrade the proto package

type GadgetRunRequest struct {
	// name of the gadget as returned by gadgetDesc.Name()
	GadgetName string `protobuf:"bytes,1,opt,name=gadgetName,proto3" json:"gadgetName,omitempty"`
	// category of the gadget as returned by gadgetDesc.Category()
	GadgetCategory string `protobuf:"bytes,2,opt,name=gadgetCategory,proto3" json:"gadgetCategory,omitempty"`
	// params is a combined map of all params a gadget could need (including those
	// of runtime and operators, which need specific prefixes, see implementation in
	// pkg/runtime/grpc)
	Params map[string]string `protobuf:"bytes,3,rep,name=params,proto3" json:"params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// args are all parameters which were not specified with a flag
	Args []string `protobuf:"bytes,4,rep,name=args,proto3" json:"args,omitempty"`
	// a list of nodes the gadget should run on; if not specified, it should run
	// on all nodes
	Nodes []string `protobuf:"bytes,10,rep,name=nodes,proto3" json:"nodes,omitempty"`
	// if set to true, the gadget service should forward the request to each node
	// from the nodes list (or each node it knows, if the list is empty) and combine
	// their output
	FanOut bool `protobuf:"varint,11,opt,name=fanOut,proto3" json:"fanOut,omitempty"`
	// sets the requested log level (see pkg/logger/logger.go)
	LogLevel uint32 `protobuf:"varint,12,opt,name=logLevel,proto3" json:"logLevel,omitempty"`
	// time that a gadget should run; use 0, if the gadget should run until it's being
	// stopped or done
	Timeout              int64    `protobuf:"varint,13,opt,name=timeout,proto3" json:"timeout,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GadgetRunRequest) Reset()         { *m = GadgetRunRequest{} }
func (m *GadgetRunRequest) String() string { return proto.CompactTextString(m) }
func (*GadgetRunRequest) ProtoMessage()    {}
func (*GadgetRunRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{0}
}

func (m *GadgetRunRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GadgetRunRequest.Unmarshal(m, b)
}
func (m *GadgetRunRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GadgetRunRequest.Marshal(b, m, deterministic)
}
func (m *GadgetRunRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GadgetRunRequest.Merge(m, src)
}
func (m *GadgetRunRequest) XXX_Size() int {
	return xxx_messageInfo_GadgetRunRequest.Size(m)
}
func (m *GadgetRunRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GadgetRunRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GadgetRunRequest proto.InternalMessageInfo

func (m *GadgetRunRequest) GetGadgetName() string {
	if m != nil {
		return m.GadgetName
	}
	return ""
}

func (m *GadgetRunRequest) GetGadgetCategory() string {
	if m != nil {
		return m.GadgetCategory
	}
	return ""
}

func (m *GadgetRunRequest) GetParams() map[string]string {
	if m != nil {
		return m.Params
	}
	return nil
}

func (m *GadgetRunRequest) GetArgs() []string {
	if m != nil {
		return m.Args
	}
	return nil
}

func (m *GadgetRunRequest) GetNodes() []string {
	if m != nil {
		return m.Nodes
	}
	return nil
}

func (m *GadgetRunRequest) GetFanOut() bool {
	if m != nil {
		return m.FanOut
	}
	return false
}

func (m *GadgetRunRequest) GetLogLevel() uint32 {
	if m != nil {
		return m.LogLevel
	}
	return 0
}

func (m *GadgetRunRequest) GetTimeout() int64 {
	if m != nil {
		return m.Timeout
	}
	return 0
}

type GadgetStopRequest struct {
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GadgetStopRequest) Reset()         { *m = GadgetStopRequest{} }
func (m *GadgetStopRequest) String() string { return proto.CompactTextString(m) }
func (*GadgetStopRequest) ProtoMessage()    {}
func (*GadgetStopRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{1}
}

func (m *GadgetStopRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GadgetStopRequest.Unmarshal(m, b)
}
func (m *GadgetStopRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GadgetStopRequest.Marshal(b, m, deterministic)
}
func (m *GadgetStopRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GadgetStopRequest.Merge(m, src)
}
func (m *GadgetStopRequest) XXX_Size() int {
	return xxx_messageInfo_GadgetStopRequest.Size(m)
}
func (m *GadgetStopRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GadgetStopRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GadgetStopRequest proto.InternalMessageInfo

type GadgetEvent struct {
	// Types are specified in consts.go. Upper 16 bits are used for log severity levels
	Type                 uint32   `protobuf:"varint,1,opt,name=type,proto3" json:"type,omitempty"`
	Seq                  uint32   `protobuf:"varint,2,opt,name=seq,proto3" json:"seq,omitempty"`
	Payload              []byte   `protobuf:"bytes,3,opt,name=payload,proto3" json:"payload,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GadgetEvent) Reset()         { *m = GadgetEvent{} }
func (m *GadgetEvent) String() string { return proto.CompactTextString(m) }
func (*GadgetEvent) ProtoMessage()    {}
func (*GadgetEvent) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{2}
}

func (m *GadgetEvent) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GadgetEvent.Unmarshal(m, b)
}
func (m *GadgetEvent) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GadgetEvent.Marshal(b, m, deterministic)
}
func (m *GadgetEvent) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GadgetEvent.Merge(m, src)
}
func (m *GadgetEvent) XXX_Size() int {
	return xxx_messageInfo_GadgetEvent.Size(m)
}
func (m *GadgetEvent) XXX_DiscardUnknown() {
	xxx_messageInfo_GadgetEvent.DiscardUnknown(m)
}

var xxx_messageInfo_GadgetEvent proto.InternalMessageInfo

func (m *GadgetEvent) GetType() uint32 {
	if m != nil {
		return m.Type
	}
	return 0
}

func (m *GadgetEvent) GetSeq() uint32 {
	if m != nil {
		return m.Seq
	}
	return 0
}

func (m *GadgetEvent) GetPayload() []byte {
	if m != nil {
		return m.Payload
	}
	return nil
}

type GadgetControlRequest struct {
	// Types that are valid to be assigned to Event:
	//	*GadgetControlRequest_RunRequest
	//	*GadgetControlRequest_StopRequest
	Event                isGadgetControlRequest_Event `protobuf_oneof:"Event"`
	XXX_NoUnkeyedLiteral struct{}                     `json:"-"`
	XXX_unrecognized     []byte                       `json:"-"`
	XXX_sizecache        int32                        `json:"-"`
}

func (m *GadgetControlRequest) Reset()         { *m = GadgetControlRequest{} }
func (m *GadgetControlRequest) String() string { return proto.CompactTextString(m) }
func (*GadgetControlRequest) ProtoMessage()    {}
func (*GadgetControlRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{3}
}

func (m *GadgetControlRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GadgetControlRequest.Unmarshal(m, b)
}
func (m *GadgetControlRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GadgetControlRequest.Marshal(b, m, deterministic)
}
func (m *GadgetControlRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GadgetControlRequest.Merge(m, src)
}
func (m *GadgetControlRequest) XXX_Size() int {
	return xxx_messageInfo_GadgetControlRequest.Size(m)
}
func (m *GadgetControlRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GadgetControlRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GadgetControlRequest proto.InternalMessageInfo

type isGadgetControlRequest_Event interface {
	isGadgetControlRequest_Event()
}

type GadgetControlRequest_RunRequest struct {
	RunRequest *GadgetRunRequest `protobuf:"bytes,1,opt,name=runRequest,proto3,oneof"`
}

type GadgetControlRequest_StopRequest struct {
	StopRequest *GadgetStopRequest `protobuf:"bytes,2,opt,name=stopRequest,proto3,oneof"`
}

func (*GadgetControlRequest_RunRequest) isGadgetControlRequest_Event() {}

func (*GadgetControlRequest_StopRequest) isGadgetControlRequest_Event() {}

func (m *GadgetControlRequest) GetEvent() isGadgetControlRequest_Event {
	if m != nil {
		return m.Event
	}
	return nil
}

func (m *GadgetControlRequest) GetRunRequest() *GadgetRunRequest {
	if x, ok := m.GetEvent().(*GadgetControlRequest_RunRequest); ok {
		return x.RunRequest
	}
	return nil
}

func (m *GadgetControlRequest) GetStopRequest() *GadgetStopRequest {
	if x, ok := m.GetEvent().(*GadgetControlRequest_StopRequest); ok {
		return x.StopRequest
	}
	return nil
}

// XXX_OneofWrappers is for the internal use of the proto package.
func (*GadgetControlRequest) XXX_OneofWrappers() []interface{} {
	return []interface{}{
		(*GadgetControlRequest_RunRequest)(nil),
		(*GadgetControlRequest_StopRequest)(nil),
	}
}

type InfoRequest struct {
	Version              string   `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *InfoRequest) Reset()         { *m = InfoRequest{} }
func (m *InfoRequest) String() string { return proto.CompactTextString(m) }
func (*InfoRequest) ProtoMessage()    {}
func (*InfoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{4}
}

func (m *InfoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_InfoRequest.Unmarshal(m, b)
}
func (m *InfoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_InfoRequest.Marshal(b, m, deterministic)
}
func (m *InfoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_InfoRequest.Merge(m, src)
}
func (m *InfoRequest) XXX_Size() int {
	return xxx_messageInfo_InfoRequest.Size(m)
}
func (m *InfoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_InfoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_InfoRequest proto.InternalMessageInfo

func (m *InfoRequest) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

type InfoResponse struct {
	Version              string   `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Catalog              []byte   `protobuf:"bytes,2,opt,name=catalog,proto3" json:"catalog,omitempty"`
	Experimental         bool     `protobuf:"varint,3,opt,name=experimental,proto3" json:"experimental,omitempty"`
	ServerVersion        string   `protobuf:"bytes,4,opt,name=serverVersion,proto3" json:"serverVersion,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *InfoResponse) Reset()         { *m = InfoResponse{} }
func (m *InfoResponse) String() string { return proto.CompactTextString(m) }
func (*InfoResponse) ProtoMessage()    {}
func (*InfoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{5}
}

func (m *InfoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_InfoResponse.Unmarshal(m, b)
}
func (m *InfoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_InfoResponse.Marshal(b, m, deterministic)
}
func (m *InfoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_InfoResponse.Merge(m, src)
}
func (m *InfoResponse) XXX_Size() int {
	return xxx_messageInfo_InfoResponse.Size(m)
}
func (m *InfoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_InfoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_InfoResponse proto.InternalMessageInfo

func (m *InfoResponse) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *InfoResponse) GetCatalog() []byte {
	if m != nil {
		return m.Catalog
	}
	return nil
}

func (m *InfoResponse) GetExperimental() bool {
	if m != nil {
		return m.Experimental
	}
	return false
}

func (m *InfoResponse) GetServerVersion() string {
	if m != nil {
		return m.ServerVersion
	}
	return ""
}

type GetGadgetInfoRequest struct {
	// params are the gadget's parameters
	Params map[string]string `protobuf:"bytes,1,rep,name=params,proto3" json:"params,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	// args are all parameters which were not specified with a flag
	Args                 []string `protobuf:"bytes,2,rep,name=args,proto3" json:"args,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetGadgetInfoRequest) Reset()         { *m = GetGadgetInfoRequest{} }
func (m *GetGadgetInfoRequest) String() string { return proto.CompactTextString(m) }
func (*GetGadgetInfoRequest) ProtoMessage()    {}
func (*GetGadgetInfoRequest) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{6}
}

func (m *GetGadgetInfoRequest) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetGadgetInfoRequest.Unmarshal(m, b)
}
func (m *GetGadgetInfoRequest) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetGadgetInfoRequest.Marshal(b, m, deterministic)
}
func (m *GetGadgetInfoRequest) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetGadgetInfoRequest.Merge(m, src)
}
func (m *GetGadgetInfoRequest) XXX_Size() int {
	return xxx_messageInfo_GetGadgetInfoRequest.Size(m)
}
func (m *GetGadgetInfoRequest) XXX_DiscardUnknown() {
	xxx_messageInfo_GetGadgetInfoRequest.DiscardUnknown(m)
}

var xxx_messageInfo_GetGadgetInfoRequest proto.InternalMessageInfo

func (m *GetGadgetInfoRequest) GetParams() map[string]string {
	if m != nil {
		return m.Params
	}
	return nil
}

func (m *GetGadgetInfoRequest) GetArgs() []string {
	if m != nil {
		return m.Args
	}
	return nil
}

type GetGadgetInfoResponse struct {
	// This is the GadgetInfo structure defined in pkg/gadgets/run/types/types.go encoded in json.
	// TODO: Ideally we should define the message here, but the implementation is changing too fast.
	// We'll make it once the implementation is more stable.
	Info                 []byte   `protobuf:"bytes,1,opt,name=info,proto3" json:"info,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *GetGadgetInfoResponse) Reset()         { *m = GetGadgetInfoResponse{} }
func (m *GetGadgetInfoResponse) String() string { return proto.CompactTextString(m) }
func (*GetGadgetInfoResponse) ProtoMessage()    {}
func (*GetGadgetInfoResponse) Descriptor() ([]byte, []int) {
	return fileDescriptor_1b40cafcd4234784, []int{7}
}

func (m *GetGadgetInfoResponse) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_GetGadgetInfoResponse.Unmarshal(m, b)
}
func (m *GetGadgetInfoResponse) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_GetGadgetInfoResponse.Marshal(b, m, deterministic)
}
func (m *GetGadgetInfoResponse) XXX_Merge(src proto.Message) {
	xxx_messageInfo_GetGadgetInfoResponse.Merge(m, src)
}
func (m *GetGadgetInfoResponse) XXX_Size() int {
	return xxx_messageInfo_GetGadgetInfoResponse.Size(m)
}
func (m *GetGadgetInfoResponse) XXX_DiscardUnknown() {
	xxx_messageInfo_GetGadgetInfoResponse.DiscardUnknown(m)
}

var xxx_messageInfo_GetGadgetInfoResponse proto.InternalMessageInfo

func (m *GetGadgetInfoResponse) GetInfo() []byte {
	if m != nil {
		return m.Info
	}
	return nil
}

func init() {
	proto.RegisterType((*GadgetRunRequest)(nil), "api.GadgetRunRequest")
	proto.RegisterMapType((map[string]string)(nil), "api.GadgetRunRequest.ParamsEntry")
	proto.RegisterType((*GadgetStopRequest)(nil), "api.GadgetStopRequest")
	proto.RegisterType((*GadgetEvent)(nil), "api.GadgetEvent")
	proto.RegisterType((*GadgetControlRequest)(nil), "api.GadgetControlRequest")
	proto.RegisterType((*InfoRequest)(nil), "api.InfoRequest")
	proto.RegisterType((*InfoResponse)(nil), "api.InfoResponse")
	proto.RegisterType((*GetGadgetInfoRequest)(nil), "api.GetGadgetInfoRequest")
	proto.RegisterMapType((map[string]string)(nil), "api.GetGadgetInfoRequest.ParamsEntry")
	proto.RegisterType((*GetGadgetInfoResponse)(nil), "api.GetGadgetInfoResponse")
}

func init() {
	proto.RegisterFile("api/api.proto", fileDescriptor_1b40cafcd4234784)
}

var fileDescriptor_1b40cafcd4234784 = []byte{
	// 606 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0xa4, 0x54, 0xcd, 0x6e, 0xd4, 0x30,
	0x10, 0x5e, 0x6f, 0xb6, 0xdd, 0x76, 0xb2, 0x41, 0x5b, 0xd3, 0x56, 0x21, 0x07, 0x14, 0x22, 0x7e,
	0x22, 0xa1, 0x6e, 0xab, 0xe5, 0x00, 0xad, 0x04, 0x87, 0x56, 0x55, 0x8b, 0x44, 0x01, 0x19, 0x89,
	0x03, 0x37, 0xb7, 0x9d, 0x86, 0xa8, 0x59, 0x3b, 0x75, 0x9c, 0x15, 0xfb, 0x0e, 0x1c, 0x79, 0x04,
	0x1e, 0x06, 0x89, 0x97, 0x42, 0xb1, 0x93, 0x6d, 0x5a, 0xb6, 0x5c, 0xb8, 0xcd, 0x7c, 0x1e, 0x7f,
	0x33, 0xdf, 0xe7, 0x91, 0xc1, 0xe3, 0x79, 0xba, 0xcd, 0xf3, 0x74, 0x94, 0x2b, 0xa9, 0x25, 0x75,
	0x78, 0x9e, 0x46, 0xbf, 0xba, 0x30, 0x3c, 0xe2, 0xe7, 0x09, 0x6a, 0x56, 0x0a, 0x86, 0x57, 0x25,
	0x16, 0x9a, 0x3e, 0x04, 0x48, 0x0c, 0xf6, 0x9e, 0x4f, 0xd0, 0x27, 0x21, 0x89, 0x57, 0x59, 0x0b,
	0xa1, 0x4f, 0xe1, 0x9e, 0xcd, 0x0e, 0xb8, 0xc6, 0x44, 0xaa, 0x99, 0xdf, 0x35, 0x35, 0xb7, 0x50,
	0xba, 0x0b, 0xcb, 0x39, 0x57, 0x7c, 0x52, 0xf8, 0x4e, 0xe8, 0xc4, 0xee, 0xf8, 0xd1, 0xa8, 0xea,
	0x7e, 0xbb, 0xdd, 0xe8, 0xa3, 0xa9, 0x39, 0x14, 0x5a, 0xcd, 0x58, 0x7d, 0x81, 0x52, 0xe8, 0x71,
	0x95, 0x14, 0x7e, 0x2f, 0x74, 0xe2, 0x55, 0x66, 0x62, 0xba, 0x0e, 0x4b, 0x42, 0x9e, 0x63, 0xe1,
	0x83, 0x01, 0x6d, 0x42, 0x37, 0x61, 0xf9, 0x82, 0x8b, 0x0f, 0xa5, 0xf6, 0xdd, 0x90, 0xc4, 0x2b,
	0xac, 0xce, 0x68, 0x00, 0x2b, 0x99, 0x4c, 0xde, 0xe1, 0x14, 0x33, 0x7f, 0x10, 0x92, 0xd8, 0x63,
	0xf3, 0x9c, 0xfa, 0xd0, 0xd7, 0xe9, 0x04, 0x65, 0xa9, 0x7d, 0x2f, 0x24, 0xb1, 0xc3, 0x9a, 0x34,
	0xd8, 0x05, 0xb7, 0x35, 0x0e, 0x1d, 0x82, 0x73, 0x89, 0xb3, 0xda, 0x82, 0x2a, 0xac, 0x86, 0x98,
	0xf2, 0xac, 0xc4, 0x5a, 0xb2, 0x4d, 0xf6, 0xba, 0xaf, 0x48, 0x74, 0x1f, 0xd6, 0xac, 0xb4, 0x4f,
	0x5a, 0xe6, 0xb5, 0xb6, 0xe8, 0x04, 0x5c, 0x0b, 0x1e, 0x4e, 0x51, 0xe8, 0x4a, 0x96, 0x9e, 0xe5,
	0xd6, 0x53, 0x8f, 0x99, 0xb8, 0xea, 0x51, 0xe0, 0x95, 0xe1, 0xf3, 0x58, 0x15, 0x56, 0xe3, 0xe5,
	0x7c, 0x96, 0x49, 0x7e, 0xee, 0x3b, 0x21, 0x89, 0x07, 0xac, 0x49, 0xa3, 0x1f, 0x04, 0xd6, 0x2d,
	0xdf, 0x81, 0x14, 0x5a, 0xc9, 0xac, 0x79, 0xb2, 0x97, 0x00, 0x6a, 0xee, 0xa8, 0xa1, 0x77, 0xc7,
	0x1b, 0x0b, 0xed, 0x3e, 0xee, 0xb0, 0x56, 0x29, 0xdd, 0x03, 0xb7, 0xb8, 0x9e, 0xd7, 0x4c, 0xe1,
	0x8e, 0x37, 0x5b, 0x37, 0x5b, 0x6a, 0x8e, 0x3b, 0xac, 0x5d, 0xbc, 0xdf, 0x87, 0x25, 0x23, 0x2b,
	0x7a, 0x06, 0xee, 0x5b, 0x71, 0x21, 0x1b, 0x4e, 0x1f, 0xfa, 0x53, 0x54, 0x45, 0x2a, 0x45, 0xed,
	0x5c, 0x93, 0x46, 0xdf, 0x09, 0x0c, 0x6c, 0x65, 0x91, 0x4b, 0x51, 0xe0, 0xdd, 0xa5, 0xd5, 0xc9,
	0x19, 0xd7, 0x3c, 0x93, 0x89, 0x19, 0x6a, 0xc0, 0x9a, 0x94, 0x46, 0x30, 0xc0, 0x6f, 0x39, 0xaa,
	0x74, 0x82, 0x42, 0xf3, 0xcc, 0x78, 0xb4, 0xc2, 0x6e, 0x60, 0xf4, 0x31, 0x78, 0x05, 0xaa, 0x29,
	0xaa, 0xcf, 0x35, 0x7b, 0xcf, 0xb0, 0xdf, 0x04, 0xa3, 0x9f, 0x95, 0x9d, 0xa8, 0xad, 0xd0, 0xb6,
	0x82, 0xd7, 0xf3, 0xcd, 0x25, 0x66, 0x73, 0x9f, 0x58, 0x43, 0x16, 0x94, 0xfe, 0x73, 0x7b, 0xbb,
	0xd7, 0xdb, 0xfb, 0x3f, 0x9b, 0xf5, 0x1c, 0x36, 0x6e, 0xb5, 0xae, 0xdd, 0xa3, 0xd0, 0x4b, 0xc5,
	0x85, 0x34, 0x2c, 0x03, 0x66, 0xe2, 0xf1, 0x6f, 0x02, 0x9e, 0x2d, 0x3d, 0xe1, 0x82, 0x27, 0xa8,
	0xe8, 0x0e, 0xf4, 0x8f, 0xec, 0x45, 0x3a, 0x34, 0x3a, 0x5a, 0xe3, 0x07, 0x6b, 0x2d, 0xc4, 0xb2,
	0x46, 0x1d, 0x7a, 0x0c, 0xde, 0x8d, 0x86, 0xf4, 0xc1, 0x9d, 0xfa, 0x83, 0x60, 0xd1, 0xd1, 0x9c,
	0xe9, 0x0d, 0xac, 0xb2, 0x52, 0xd8, 0xa3, 0x86, 0x65, 0xc1, 0xfe, 0x06, 0xc3, 0xd6, 0x91, 0xdd,
	0xa9, 0x4e, 0x4c, 0x76, 0xc8, 0xfe, 0xe1, 0x97, 0x83, 0x24, 0xd5, 0x5f, 0xcb, 0xd3, 0xd1, 0x99,
	0x9c, 0x6c, 0xa7, 0xa2, 0xc8, 0xf1, 0x52, 0x4b, 0xb5, 0x65, 0x7f, 0x9a, 0xbf, 0x81, 0xfc, 0x32,
	0xd9, 0xb6, 0xe1, 0x56, 0xf5, 0xd4, 0xe9, 0x19, 0x56, 0x3f, 0xde, 0xe9, 0xb2, 0xf9, 0xf2, 0x5e,
	0xfc, 0x09, 0x00, 0x00, 0xff, 0xff, 0x46, 0xc0, 0x2e, 0x30, 0x03, 0x05, 0x00, 0x00,
}
