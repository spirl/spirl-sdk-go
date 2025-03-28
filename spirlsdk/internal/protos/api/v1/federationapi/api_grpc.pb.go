// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: api/v1/federationapi/api.proto

package federationapi

import (
	context "context"
	grpc "google.golang.org/grpc"
	codes "google.golang.org/grpc/codes"
	status "google.golang.org/grpc/status"
)

// This is a compile-time assertion to ensure that this generated file
// is compatible with the grpc package it is being compiled against.
// Requires gRPC-Go v1.64.0 or later.
const _ = grpc.SupportPackageIsVersion9

const (
	API_SetLink_FullMethodName     = "/com.spirl.api.v1.federation.API/SetLink"
	API_DeleteLink_FullMethodName  = "/com.spirl.api.v1.federation.API/DeleteLink"
	API_ListLinks_FullMethodName   = "/com.spirl.api.v1.federation.API/ListLinks"
	API_RefreshLink_FullMethodName = "/com.spirl.api.v1.federation.API/RefreshLink"
)

// APIClient is the client API for API service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type APIClient interface {
	SetLink(ctx context.Context, in *SetLinkRequest, opts ...grpc.CallOption) (*SetLinkResponse, error)
	DeleteLink(ctx context.Context, in *DeleteLinkRequest, opts ...grpc.CallOption) (*DeleteLinkResponse, error)
	ListLinks(ctx context.Context, in *ListLinksRequest, opts ...grpc.CallOption) (*ListLinksResponse, error)
	RefreshLink(ctx context.Context, in *RefreshLinkRequest, opts ...grpc.CallOption) (*RefreshLinkResponse, error)
}

type aPIClient struct {
	cc grpc.ClientConnInterface
}

func NewAPIClient(cc grpc.ClientConnInterface) APIClient {
	return &aPIClient{cc}
}

func (c *aPIClient) SetLink(ctx context.Context, in *SetLinkRequest, opts ...grpc.CallOption) (*SetLinkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(SetLinkResponse)
	err := c.cc.Invoke(ctx, API_SetLink_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) DeleteLink(ctx context.Context, in *DeleteLinkRequest, opts ...grpc.CallOption) (*DeleteLinkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteLinkResponse)
	err := c.cc.Invoke(ctx, API_DeleteLink_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) ListLinks(ctx context.Context, in *ListLinksRequest, opts ...grpc.CallOption) (*ListLinksResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListLinksResponse)
	err := c.cc.Invoke(ctx, API_ListLinks_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) RefreshLink(ctx context.Context, in *RefreshLinkRequest, opts ...grpc.CallOption) (*RefreshLinkResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RefreshLinkResponse)
	err := c.cc.Invoke(ctx, API_RefreshLink_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// APIServer is the server API for API service.
// All implementations must embed UnimplementedAPIServer
// for forward compatibility.
type APIServer interface {
	SetLink(context.Context, *SetLinkRequest) (*SetLinkResponse, error)
	DeleteLink(context.Context, *DeleteLinkRequest) (*DeleteLinkResponse, error)
	ListLinks(context.Context, *ListLinksRequest) (*ListLinksResponse, error)
	RefreshLink(context.Context, *RefreshLinkRequest) (*RefreshLinkResponse, error)
	mustEmbedUnimplementedAPIServer()
}

// UnimplementedAPIServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedAPIServer struct{}

func (UnimplementedAPIServer) SetLink(context.Context, *SetLinkRequest) (*SetLinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method SetLink not implemented")
}
func (UnimplementedAPIServer) DeleteLink(context.Context, *DeleteLinkRequest) (*DeleteLinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteLink not implemented")
}
func (UnimplementedAPIServer) ListLinks(context.Context, *ListLinksRequest) (*ListLinksResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListLinks not implemented")
}
func (UnimplementedAPIServer) RefreshLink(context.Context, *RefreshLinkRequest) (*RefreshLinkResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RefreshLink not implemented")
}
func (UnimplementedAPIServer) mustEmbedUnimplementedAPIServer() {}
func (UnimplementedAPIServer) testEmbeddedByValue()             {}

// UnsafeAPIServer may be embedded to opt out of forward compatibility for this service.
// Use of this interface is not recommended, as added methods to APIServer will
// result in compilation errors.
type UnsafeAPIServer interface {
	mustEmbedUnimplementedAPIServer()
}

func RegisterAPIServer(s grpc.ServiceRegistrar, srv APIServer) {
	// If the following call pancis, it indicates UnimplementedAPIServer was
	// embedded by pointer and is nil.  This will cause panics if an
	// unimplemented method is ever invoked, so we test this at initialization
	// time to prevent it from happening at runtime later due to I/O.
	if t, ok := srv.(interface{ testEmbeddedByValue() }); ok {
		t.testEmbeddedByValue()
	}
	s.RegisterService(&API_ServiceDesc, srv)
}

func _API_SetLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(SetLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).SetLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_SetLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).SetLink(ctx, req.(*SetLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_DeleteLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).DeleteLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_DeleteLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).DeleteLink(ctx, req.(*DeleteLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_ListLinks_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListLinksRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).ListLinks(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_ListLinks_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).ListLinks(ctx, req.(*ListLinksRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_RefreshLink_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RefreshLinkRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).RefreshLink(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_RefreshLink_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).RefreshLink(ctx, req.(*RefreshLinkRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// API_ServiceDesc is the grpc.ServiceDesc for API service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var API_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.spirl.api.v1.federation.API",
	HandlerType: (*APIServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "SetLink",
			Handler:    _API_SetLink_Handler,
		},
		{
			MethodName: "DeleteLink",
			Handler:    _API_DeleteLink_Handler,
		},
		{
			MethodName: "ListLinks",
			Handler:    _API_ListLinks_Handler,
		},
		{
			MethodName: "RefreshLink",
			Handler:    _API_RefreshLink_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/federationapi/api.proto",
}
