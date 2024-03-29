// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.2.0
// - protoc             v3.17.3
// source: api/api.proto

package api

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.32.0 or later.
const _ = grpc.SupportPackageIsVersion7

// GadgetManagerClient is the client API for GadgetManager service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type GadgetManagerClient interface {
	GetInfo(ctx context.Context, in *InfoRequest, opts ...grpc.CallOption) (*InfoResponse, error)
	GetGadgetInfo(ctx context.Context, in *GetGadgetInfoRequest, opts ...grpc.CallOption) (*GetGadgetInfoResponse, error)
	RunGadget(ctx context.Context, opts ...grpc.CallOption) (GadgetManager_RunGadgetClient, error)
}

type gadgetManagerClient struct {
	cc grpc.ClientConnInterface
}

func NewGadgetManagerClient(cc grpc.ClientConnInterface) GadgetManagerClient {
	return &gadgetManagerClient{cc}
}

func (c *gadgetManagerClient) GetInfo(ctx context.Context, in *InfoRequest, opts ...grpc.CallOption) (*InfoResponse, error) {
	out := new(InfoResponse)
	err := c.cc.Invoke(ctx, "/api.GadgetManager/GetInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetManagerClient) GetGadgetInfo(ctx context.Context, in *GetGadgetInfoRequest, opts ...grpc.CallOption) (*GetGadgetInfoResponse, error) {
	out := new(GetGadgetInfoResponse)
	err := c.cc.Invoke(ctx, "/api.GadgetManager/GetGadgetInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *gadgetManagerClient) RunGadget(ctx context.Context, opts ...grpc.CallOption) (GadgetManager_RunGadgetClient, error) {
	stream, err := c.cc.NewStream(ctx, &GadgetManager_ServiceDesc.Streams[0], "/api.GadgetManager/RunGadget", opts...)
	if err != nil {
		return nil, err
	}
	x := &gadgetManagerRunGadgetClient{stream}
	return x, nil
}

type GadgetManager_RunGadgetClient interface {
	Send(*GadgetControlRequest) error
	Recv() (*GadgetEvent, error)
	grpc.ClientStream
}

type gadgetManagerRunGadgetClient struct {
	grpc.ClientStream
}

func (x *gadgetManagerRunGadgetClient) Send(m *GadgetControlRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *gadgetManagerRunGadgetClient) Recv() (*GadgetEvent, error) {
	m := new(GadgetEvent)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// GadgetManagerServer is the server API for GadgetManager service.
// All implementations must embed UnimplementedGadgetManagerServer
// for forward compatibility
type GadgetManagerServer interface {
	GetInfo(context.Context, *InfoRequest) (*InfoResponse, error)
	GetGadgetInfo(context.Context, *GetGadgetInfoRequest) (*GetGadgetInfoResponse, error)
	RunGadget(GadgetManager_RunGadgetServer) error
	mustEmbedUnimplementedGadgetManagerServer()
}

// UnimplementedGadgetManagerServer must be embedded to have forward compatible implementations.
type UnimplementedGadgetManagerServer struct {
}

func (UnimplementedGadgetManagerServer) GetInfo(context.Context, *InfoRequest) (*InfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetInfo not implemented")
}
func (UnimplementedGadgetManagerServer) GetGadgetInfo(context.Context, *GetGadgetInfoRequest) (*GetGadgetInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetGadgetInfo not implemented")
}
func (UnimplementedGadgetManagerServer) RunGadget(GadgetManager_RunGadgetServer) error {
	return status.Errorf(codes.Unimplemented, "method RunGadget not implemented")
}
func (UnimplementedGadgetManagerServer) mustEmbedUnimplementedGadgetManagerServer() {}

// UnsafeGadgetManagerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to GadgetManagerServer will
// result in compilation errors.
type UnsafeGadgetManagerServer interface {
	mustEmbedUnimplementedGadgetManagerServer()
}

func RegisterGadgetManagerServer(s grpc.ServiceRegistrar, srv GadgetManagerServer) {
	s.RegisterService(&GadgetManager_ServiceDesc, srv)
}

func _GadgetManager_GetInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(InfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetManagerServer).GetInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.GadgetManager/GetInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetManagerServer).GetInfo(ctx, req.(*InfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetManager_GetGadgetInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetGadgetInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(GadgetManagerServer).GetGadgetInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.GadgetManager/GetGadgetInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(GadgetManagerServer).GetGadgetInfo(ctx, req.(*GetGadgetInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _GadgetManager_RunGadget_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(GadgetManagerServer).RunGadget(&gadgetManagerRunGadgetServer{stream})
}

type GadgetManager_RunGadgetServer interface {
	Send(*GadgetEvent) error
	Recv() (*GadgetControlRequest, error)
	grpc.ServerStream
}

type gadgetManagerRunGadgetServer struct {
	grpc.ServerStream
}

func (x *gadgetManagerRunGadgetServer) Send(m *GadgetEvent) error {
	return x.ServerStream.SendMsg(m)
}

func (x *gadgetManagerRunGadgetServer) Recv() (*GadgetControlRequest, error) {
	m := new(GadgetControlRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// GadgetManager_ServiceDesc is the grpc.ServiceDesc for GadgetManager service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var GadgetManager_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.GadgetManager",
	HandlerType: (*GadgetManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetInfo",
			Handler:    _GadgetManager_GetInfo_Handler,
		},
		{
			MethodName: "GetGadgetInfo",
			Handler:    _GadgetManager_GetGadgetInfo_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RunGadget",
			Handler:       _GadgetManager_RunGadget_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "api/api.proto",
}

// OCIGadgetManagerClient is the client API for OCIGadgetManager service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type OCIGadgetManagerClient interface {
	GetOCIGadgetInfo(ctx context.Context, in *GetOCIGadgetInfoRequest, opts ...grpc.CallOption) (*GetOCIGadgetInfoResponse, error)
	RunOCIGadget(ctx context.Context, opts ...grpc.CallOption) (OCIGadgetManager_RunOCIGadgetClient, error)
}

type oCIGadgetManagerClient struct {
	cc grpc.ClientConnInterface
}

func NewOCIGadgetManagerClient(cc grpc.ClientConnInterface) OCIGadgetManagerClient {
	return &oCIGadgetManagerClient{cc}
}

func (c *oCIGadgetManagerClient) GetOCIGadgetInfo(ctx context.Context, in *GetOCIGadgetInfoRequest, opts ...grpc.CallOption) (*GetOCIGadgetInfoResponse, error) {
	out := new(GetOCIGadgetInfoResponse)
	err := c.cc.Invoke(ctx, "/api.OCIGadgetManager/GetOCIGadgetInfo", in, out, opts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *oCIGadgetManagerClient) RunOCIGadget(ctx context.Context, opts ...grpc.CallOption) (OCIGadgetManager_RunOCIGadgetClient, error) {
	stream, err := c.cc.NewStream(ctx, &OCIGadgetManager_ServiceDesc.Streams[0], "/api.OCIGadgetManager/RunOCIGadget", opts...)
	if err != nil {
		return nil, err
	}
	x := &oCIGadgetManagerRunOCIGadgetClient{stream}
	return x, nil
}

type OCIGadgetManager_RunOCIGadgetClient interface {
	Send(*OCIGadgetControlRequest) error
	Recv() (*GadgetEvent, error)
	grpc.ClientStream
}

type oCIGadgetManagerRunOCIGadgetClient struct {
	grpc.ClientStream
}

func (x *oCIGadgetManagerRunOCIGadgetClient) Send(m *OCIGadgetControlRequest) error {
	return x.ClientStream.SendMsg(m)
}

func (x *oCIGadgetManagerRunOCIGadgetClient) Recv() (*GadgetEvent, error) {
	m := new(GadgetEvent)
	if err := x.ClientStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// OCIGadgetManagerServer is the server API for OCIGadgetManager service.
// All implementations must embed UnimplementedOCIGadgetManagerServer
// for forward compatibility
type OCIGadgetManagerServer interface {
	GetOCIGadgetInfo(context.Context, *GetOCIGadgetInfoRequest) (*GetOCIGadgetInfoResponse, error)
	RunOCIGadget(OCIGadgetManager_RunOCIGadgetServer) error
	mustEmbedUnimplementedOCIGadgetManagerServer()
}

// UnimplementedOCIGadgetManagerServer must be embedded to have forward compatible implementations.
type UnimplementedOCIGadgetManagerServer struct {
}

func (UnimplementedOCIGadgetManagerServer) GetOCIGadgetInfo(context.Context, *GetOCIGadgetInfoRequest) (*GetOCIGadgetInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetOCIGadgetInfo not implemented")
}
func (UnimplementedOCIGadgetManagerServer) RunOCIGadget(OCIGadgetManager_RunOCIGadgetServer) error {
	return status.Errorf(codes.Unimplemented, "method RunOCIGadget not implemented")
}
func (UnimplementedOCIGadgetManagerServer) mustEmbedUnimplementedOCIGadgetManagerServer() {}

// UnsafeOCIGadgetManagerServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to OCIGadgetManagerServer will
// result in compilation errors.
type UnsafeOCIGadgetManagerServer interface {
	mustEmbedUnimplementedOCIGadgetManagerServer()
}

func RegisterOCIGadgetManagerServer(s grpc.ServiceRegistrar, srv OCIGadgetManagerServer) {
	s.RegisterService(&OCIGadgetManager_ServiceDesc, srv)
}

func _OCIGadgetManager_GetOCIGadgetInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetOCIGadgetInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(OCIGadgetManagerServer).GetOCIGadgetInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: "/api.OCIGadgetManager/GetOCIGadgetInfo",
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(OCIGadgetManagerServer).GetOCIGadgetInfo(ctx, req.(*GetOCIGadgetInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _OCIGadgetManager_RunOCIGadget_Handler(srv interface{}, stream grpc.ServerStream) error {
	return srv.(OCIGadgetManagerServer).RunOCIGadget(&oCIGadgetManagerRunOCIGadgetServer{stream})
}

type OCIGadgetManager_RunOCIGadgetServer interface {
	Send(*GadgetEvent) error
	Recv() (*OCIGadgetControlRequest, error)
	grpc.ServerStream
}

type oCIGadgetManagerRunOCIGadgetServer struct {
	grpc.ServerStream
}

func (x *oCIGadgetManagerRunOCIGadgetServer) Send(m *GadgetEvent) error {
	return x.ServerStream.SendMsg(m)
}

func (x *oCIGadgetManagerRunOCIGadgetServer) Recv() (*OCIGadgetControlRequest, error) {
	m := new(OCIGadgetControlRequest)
	if err := x.ServerStream.RecvMsg(m); err != nil {
		return nil, err
	}
	return m, nil
}

// OCIGadgetManager_ServiceDesc is the grpc.ServiceDesc for OCIGadgetManager service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var OCIGadgetManager_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "api.OCIGadgetManager",
	HandlerType: (*OCIGadgetManagerServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "GetOCIGadgetInfo",
			Handler:    _OCIGadgetManager_GetOCIGadgetInfo_Handler,
		},
	},
	Streams: []grpc.StreamDesc{
		{
			StreamName:    "RunOCIGadget",
			Handler:       _OCIGadgetManager_RunOCIGadget_Handler,
			ServerStreams: true,
			ClientStreams: true,
		},
	},
	Metadata: "api/api.proto",
}
