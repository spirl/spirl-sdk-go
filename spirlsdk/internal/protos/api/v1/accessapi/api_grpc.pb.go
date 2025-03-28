// Code generated by protoc-gen-go-grpc. DO NOT EDIT.
// versions:
// - protoc-gen-go-grpc v1.5.1
// - protoc             (unknown)
// source: api/v1/accessapi/api.proto

package accessapi

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
	API_ListOrgRoles_FullMethodName                  = "/com.spirl.api.v1.access.API/ListOrgRoles"
	API_ListUsers_FullMethodName                     = "/com.spirl.api.v1.access.API/ListUsers"
	API_UpdateUserRole_FullMethodName                = "/com.spirl.api.v1.access.API/UpdateUserRole"
	API_DeleteUser_FullMethodName                    = "/com.spirl.api.v1.access.API/DeleteUser"
	API_CreateUserInvitation_FullMethodName          = "/com.spirl.api.v1.access.API/CreateUserInvitation"
	API_RenewUserInvitation_FullMethodName           = "/com.spirl.api.v1.access.API/RenewUserInvitation"
	API_DeleteUserInvitation_FullMethodName          = "/com.spirl.api.v1.access.API/DeleteUserInvitation"
	API_ListUserInvitations_FullMethodName           = "/com.spirl.api.v1.access.API/ListUserInvitations"
	API_CreateServiceAccount_FullMethodName          = "/com.spirl.api.v1.access.API/CreateServiceAccount"
	API_ListServiceAccounts_FullMethodName           = "/com.spirl.api.v1.access.API/ListServiceAccounts"
	API_GetServiceAccountInfo_FullMethodName         = "/com.spirl.api.v1.access.API/GetServiceAccountInfo"
	API_UpdateServiceAccountRole_FullMethodName      = "/com.spirl.api.v1.access.API/UpdateServiceAccountRole"
	API_DeleteServiceAccount_FullMethodName          = "/com.spirl.api.v1.access.API/DeleteServiceAccount"
	API_CreateServiceAccountKey_FullMethodName       = "/com.spirl.api.v1.access.API/CreateServiceAccountKey"
	API_DeleteServiceAccountKey_FullMethodName       = "/com.spirl.api.v1.access.API/DeleteServiceAccountKey"
	API_UpdateServiceAccountKeyStatus_FullMethodName = "/com.spirl.api.v1.access.API/UpdateServiceAccountKeyStatus"
	API_ListAuditLogs_FullMethodName                 = "/com.spirl.api.v1.access.API/ListAuditLogs"
)

// APIClient is the client API for API service.
//
// For semantics around ctx use and closing/ending streaming RPCs, please refer to https://pkg.go.dev/google.golang.org/grpc/?tab=doc#ClientConn.NewStream.
type APIClient interface {
	// Lists the organization roles.
	ListOrgRoles(ctx context.Context, in *ListOrgRolesRequest, opts ...grpc.CallOption) (*ListOrgRolesResponse, error)
	// Lists users in the organization.
	ListUsers(ctx context.Context, in *ListUsersRequest, opts ...grpc.CallOption) (*ListUsersResponse, error)
	// Updates the role of a user in the organization.
	UpdateUserRole(ctx context.Context, in *UpdateUserRoleRequest, opts ...grpc.CallOption) (*UpdateUserRoleResponse, error)
	// Deletes a user in the organization.
	DeleteUser(ctx context.Context, in *DeleteUserRequest, opts ...grpc.CallOption) (*DeleteUserResponse, error)
	// Creates an invitation to the organization.
	CreateUserInvitation(ctx context.Context, in *CreateUserInvitationRequest, opts ...grpc.CallOption) (*CreateUserInvitationResponse, error)
	// Renews an user invitation by setting a new expiration date.
	RenewUserInvitation(ctx context.Context, in *RenewUserInvitationRequest, opts ...grpc.CallOption) (*RenewUserInvitationResponse, error)
	// Deletes an invitation to the organization.
	DeleteUserInvitation(ctx context.Context, in *DeleteUserInvitationRequest, opts ...grpc.CallOption) (*DeleteUserInvitationResponse, error)
	// Lists the invitation to the organization.
	ListUserInvitations(ctx context.Context, in *ListUserInvitationsRequest, opts ...grpc.CallOption) (*ListUserInvitationsResponse, error)
	// Creates a new service account with the given name and role, the description
	// is optional. The role must not have more permissions than the role of the
	// authenticated user.
	CreateServiceAccount(ctx context.Context, in *CreateServiceAccountRequest, opts ...grpc.CallOption) (*CreateServiceAccountResponse, error)
	// Returns a list of all service accounts for the organization.
	ListServiceAccounts(ctx context.Context, in *ListServiceAccountsRequest, opts ...grpc.CallOption) (*ListServiceAccountsResponse, error)
	// Returns the service account for the given id, including all keys.
	GetServiceAccountInfo(ctx context.Context, in *GetServiceAccountInfoRequest, opts ...grpc.CallOption) (*GetServiceAccountInfoResponse, error)
	// Changes the role of the given service account. The role must not have more
	// permissions than the role of the authenticated user.
	UpdateServiceAccountRole(ctx context.Context, in *UpdateServiceAccountRoleRequest, opts ...grpc.CallOption) (*UpdateServiceAccountRoleResponse, error)
	// Deletes the service account with the given id. A service account can only
	// be deleted if it has no active keys.
	DeleteServiceAccount(ctx context.Context, in *DeleteServiceAccountRequest, opts ...grpc.CallOption) (*DeleteServiceAccountResponse, error)
	// Creates and add a new key to the given service account. The key must be a
	// valid ed25519 public key.
	CreateServiceAccountKey(ctx context.Context, in *CreateServiceAccountKeyRequest, opts ...grpc.CallOption) (*CreateServiceAccountKeyResponse, error)
	// Deletes the key with the given id from the service account. A key can only
	// be removed if it is not active.
	DeleteServiceAccountKey(ctx context.Context, in *DeleteServiceAccountKeyRequest, opts ...grpc.CallOption) (*DeleteServiceAccountKeyResponse, error)
	// Updates the active status of the key with the given id.
	UpdateServiceAccountKeyStatus(ctx context.Context, in *UpdateServiceAccountKeyStatusRequest, opts ...grpc.CallOption) (*UpdateServiceAccountKeyStatusResponse, error)
	// Lists the audit logs for the organization.
	ListAuditLogs(ctx context.Context, in *ListAuditLogsRequest, opts ...grpc.CallOption) (*ListAuditLogsResponse, error)
}

type aPIClient struct {
	cc grpc.ClientConnInterface
}

func NewAPIClient(cc grpc.ClientConnInterface) APIClient {
	return &aPIClient{cc}
}

func (c *aPIClient) ListOrgRoles(ctx context.Context, in *ListOrgRolesRequest, opts ...grpc.CallOption) (*ListOrgRolesResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListOrgRolesResponse)
	err := c.cc.Invoke(ctx, API_ListOrgRoles_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) ListUsers(ctx context.Context, in *ListUsersRequest, opts ...grpc.CallOption) (*ListUsersResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListUsersResponse)
	err := c.cc.Invoke(ctx, API_ListUsers_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) UpdateUserRole(ctx context.Context, in *UpdateUserRoleRequest, opts ...grpc.CallOption) (*UpdateUserRoleResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UpdateUserRoleResponse)
	err := c.cc.Invoke(ctx, API_UpdateUserRole_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) DeleteUser(ctx context.Context, in *DeleteUserRequest, opts ...grpc.CallOption) (*DeleteUserResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteUserResponse)
	err := c.cc.Invoke(ctx, API_DeleteUser_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) CreateUserInvitation(ctx context.Context, in *CreateUserInvitationRequest, opts ...grpc.CallOption) (*CreateUserInvitationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateUserInvitationResponse)
	err := c.cc.Invoke(ctx, API_CreateUserInvitation_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) RenewUserInvitation(ctx context.Context, in *RenewUserInvitationRequest, opts ...grpc.CallOption) (*RenewUserInvitationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(RenewUserInvitationResponse)
	err := c.cc.Invoke(ctx, API_RenewUserInvitation_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) DeleteUserInvitation(ctx context.Context, in *DeleteUserInvitationRequest, opts ...grpc.CallOption) (*DeleteUserInvitationResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteUserInvitationResponse)
	err := c.cc.Invoke(ctx, API_DeleteUserInvitation_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) ListUserInvitations(ctx context.Context, in *ListUserInvitationsRequest, opts ...grpc.CallOption) (*ListUserInvitationsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListUserInvitationsResponse)
	err := c.cc.Invoke(ctx, API_ListUserInvitations_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) CreateServiceAccount(ctx context.Context, in *CreateServiceAccountRequest, opts ...grpc.CallOption) (*CreateServiceAccountResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateServiceAccountResponse)
	err := c.cc.Invoke(ctx, API_CreateServiceAccount_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) ListServiceAccounts(ctx context.Context, in *ListServiceAccountsRequest, opts ...grpc.CallOption) (*ListServiceAccountsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListServiceAccountsResponse)
	err := c.cc.Invoke(ctx, API_ListServiceAccounts_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) GetServiceAccountInfo(ctx context.Context, in *GetServiceAccountInfoRequest, opts ...grpc.CallOption) (*GetServiceAccountInfoResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(GetServiceAccountInfoResponse)
	err := c.cc.Invoke(ctx, API_GetServiceAccountInfo_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) UpdateServiceAccountRole(ctx context.Context, in *UpdateServiceAccountRoleRequest, opts ...grpc.CallOption) (*UpdateServiceAccountRoleResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UpdateServiceAccountRoleResponse)
	err := c.cc.Invoke(ctx, API_UpdateServiceAccountRole_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) DeleteServiceAccount(ctx context.Context, in *DeleteServiceAccountRequest, opts ...grpc.CallOption) (*DeleteServiceAccountResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteServiceAccountResponse)
	err := c.cc.Invoke(ctx, API_DeleteServiceAccount_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) CreateServiceAccountKey(ctx context.Context, in *CreateServiceAccountKeyRequest, opts ...grpc.CallOption) (*CreateServiceAccountKeyResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(CreateServiceAccountKeyResponse)
	err := c.cc.Invoke(ctx, API_CreateServiceAccountKey_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) DeleteServiceAccountKey(ctx context.Context, in *DeleteServiceAccountKeyRequest, opts ...grpc.CallOption) (*DeleteServiceAccountKeyResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(DeleteServiceAccountKeyResponse)
	err := c.cc.Invoke(ctx, API_DeleteServiceAccountKey_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) UpdateServiceAccountKeyStatus(ctx context.Context, in *UpdateServiceAccountKeyStatusRequest, opts ...grpc.CallOption) (*UpdateServiceAccountKeyStatusResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(UpdateServiceAccountKeyStatusResponse)
	err := c.cc.Invoke(ctx, API_UpdateServiceAccountKeyStatus_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func (c *aPIClient) ListAuditLogs(ctx context.Context, in *ListAuditLogsRequest, opts ...grpc.CallOption) (*ListAuditLogsResponse, error) {
	cOpts := append([]grpc.CallOption{grpc.StaticMethod()}, opts...)
	out := new(ListAuditLogsResponse)
	err := c.cc.Invoke(ctx, API_ListAuditLogs_FullMethodName, in, out, cOpts...)
	if err != nil {
		return nil, err
	}
	return out, nil
}

// APIServer is the server API for API service.
// All implementations must embed UnimplementedAPIServer
// for forward compatibility.
type APIServer interface {
	// Lists the organization roles.
	ListOrgRoles(context.Context, *ListOrgRolesRequest) (*ListOrgRolesResponse, error)
	// Lists users in the organization.
	ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error)
	// Updates the role of a user in the organization.
	UpdateUserRole(context.Context, *UpdateUserRoleRequest) (*UpdateUserRoleResponse, error)
	// Deletes a user in the organization.
	DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error)
	// Creates an invitation to the organization.
	CreateUserInvitation(context.Context, *CreateUserInvitationRequest) (*CreateUserInvitationResponse, error)
	// Renews an user invitation by setting a new expiration date.
	RenewUserInvitation(context.Context, *RenewUserInvitationRequest) (*RenewUserInvitationResponse, error)
	// Deletes an invitation to the organization.
	DeleteUserInvitation(context.Context, *DeleteUserInvitationRequest) (*DeleteUserInvitationResponse, error)
	// Lists the invitation to the organization.
	ListUserInvitations(context.Context, *ListUserInvitationsRequest) (*ListUserInvitationsResponse, error)
	// Creates a new service account with the given name and role, the description
	// is optional. The role must not have more permissions than the role of the
	// authenticated user.
	CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error)
	// Returns a list of all service accounts for the organization.
	ListServiceAccounts(context.Context, *ListServiceAccountsRequest) (*ListServiceAccountsResponse, error)
	// Returns the service account for the given id, including all keys.
	GetServiceAccountInfo(context.Context, *GetServiceAccountInfoRequest) (*GetServiceAccountInfoResponse, error)
	// Changes the role of the given service account. The role must not have more
	// permissions than the role of the authenticated user.
	UpdateServiceAccountRole(context.Context, *UpdateServiceAccountRoleRequest) (*UpdateServiceAccountRoleResponse, error)
	// Deletes the service account with the given id. A service account can only
	// be deleted if it has no active keys.
	DeleteServiceAccount(context.Context, *DeleteServiceAccountRequest) (*DeleteServiceAccountResponse, error)
	// Creates and add a new key to the given service account. The key must be a
	// valid ed25519 public key.
	CreateServiceAccountKey(context.Context, *CreateServiceAccountKeyRequest) (*CreateServiceAccountKeyResponse, error)
	// Deletes the key with the given id from the service account. A key can only
	// be removed if it is not active.
	DeleteServiceAccountKey(context.Context, *DeleteServiceAccountKeyRequest) (*DeleteServiceAccountKeyResponse, error)
	// Updates the active status of the key with the given id.
	UpdateServiceAccountKeyStatus(context.Context, *UpdateServiceAccountKeyStatusRequest) (*UpdateServiceAccountKeyStatusResponse, error)
	// Lists the audit logs for the organization.
	ListAuditLogs(context.Context, *ListAuditLogsRequest) (*ListAuditLogsResponse, error)
	mustEmbedUnimplementedAPIServer()
}

// UnimplementedAPIServer must be embedded to have
// forward compatible implementations.
//
// NOTE: this should be embedded by value instead of pointer to avoid a nil
// pointer dereference when methods are called.
type UnimplementedAPIServer struct{}

func (UnimplementedAPIServer) ListOrgRoles(context.Context, *ListOrgRolesRequest) (*ListOrgRolesResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListOrgRoles not implemented")
}
func (UnimplementedAPIServer) ListUsers(context.Context, *ListUsersRequest) (*ListUsersResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUsers not implemented")
}
func (UnimplementedAPIServer) UpdateUserRole(context.Context, *UpdateUserRoleRequest) (*UpdateUserRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateUserRole not implemented")
}
func (UnimplementedAPIServer) DeleteUser(context.Context, *DeleteUserRequest) (*DeleteUserResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUser not implemented")
}
func (UnimplementedAPIServer) CreateUserInvitation(context.Context, *CreateUserInvitationRequest) (*CreateUserInvitationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateUserInvitation not implemented")
}
func (UnimplementedAPIServer) RenewUserInvitation(context.Context, *RenewUserInvitationRequest) (*RenewUserInvitationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method RenewUserInvitation not implemented")
}
func (UnimplementedAPIServer) DeleteUserInvitation(context.Context, *DeleteUserInvitationRequest) (*DeleteUserInvitationResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteUserInvitation not implemented")
}
func (UnimplementedAPIServer) ListUserInvitations(context.Context, *ListUserInvitationsRequest) (*ListUserInvitationsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListUserInvitations not implemented")
}
func (UnimplementedAPIServer) CreateServiceAccount(context.Context, *CreateServiceAccountRequest) (*CreateServiceAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateServiceAccount not implemented")
}
func (UnimplementedAPIServer) ListServiceAccounts(context.Context, *ListServiceAccountsRequest) (*ListServiceAccountsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListServiceAccounts not implemented")
}
func (UnimplementedAPIServer) GetServiceAccountInfo(context.Context, *GetServiceAccountInfoRequest) (*GetServiceAccountInfoResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method GetServiceAccountInfo not implemented")
}
func (UnimplementedAPIServer) UpdateServiceAccountRole(context.Context, *UpdateServiceAccountRoleRequest) (*UpdateServiceAccountRoleResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateServiceAccountRole not implemented")
}
func (UnimplementedAPIServer) DeleteServiceAccount(context.Context, *DeleteServiceAccountRequest) (*DeleteServiceAccountResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteServiceAccount not implemented")
}
func (UnimplementedAPIServer) CreateServiceAccountKey(context.Context, *CreateServiceAccountKeyRequest) (*CreateServiceAccountKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method CreateServiceAccountKey not implemented")
}
func (UnimplementedAPIServer) DeleteServiceAccountKey(context.Context, *DeleteServiceAccountKeyRequest) (*DeleteServiceAccountKeyResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method DeleteServiceAccountKey not implemented")
}
func (UnimplementedAPIServer) UpdateServiceAccountKeyStatus(context.Context, *UpdateServiceAccountKeyStatusRequest) (*UpdateServiceAccountKeyStatusResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method UpdateServiceAccountKeyStatus not implemented")
}
func (UnimplementedAPIServer) ListAuditLogs(context.Context, *ListAuditLogsRequest) (*ListAuditLogsResponse, error) {
	return nil, status.Errorf(codes.Unimplemented, "method ListAuditLogs not implemented")
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

func _API_ListOrgRoles_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListOrgRolesRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).ListOrgRoles(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_ListOrgRoles_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).ListOrgRoles(ctx, req.(*ListOrgRolesRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_ListUsers_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUsersRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).ListUsers(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_ListUsers_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).ListUsers(ctx, req.(*ListUsersRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_UpdateUserRole_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateUserRoleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).UpdateUserRole(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_UpdateUserRole_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).UpdateUserRole(ctx, req.(*UpdateUserRoleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_DeleteUser_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).DeleteUser(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_DeleteUser_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).DeleteUser(ctx, req.(*DeleteUserRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_CreateUserInvitation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateUserInvitationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).CreateUserInvitation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_CreateUserInvitation_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).CreateUserInvitation(ctx, req.(*CreateUserInvitationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_RenewUserInvitation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(RenewUserInvitationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).RenewUserInvitation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_RenewUserInvitation_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).RenewUserInvitation(ctx, req.(*RenewUserInvitationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_DeleteUserInvitation_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteUserInvitationRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).DeleteUserInvitation(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_DeleteUserInvitation_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).DeleteUserInvitation(ctx, req.(*DeleteUserInvitationRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_ListUserInvitations_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListUserInvitationsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).ListUserInvitations(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_ListUserInvitations_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).ListUserInvitations(ctx, req.(*ListUserInvitationsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_CreateServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).CreateServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_CreateServiceAccount_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).CreateServiceAccount(ctx, req.(*CreateServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_ListServiceAccounts_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListServiceAccountsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).ListServiceAccounts(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_ListServiceAccounts_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).ListServiceAccounts(ctx, req.(*ListServiceAccountsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_GetServiceAccountInfo_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(GetServiceAccountInfoRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).GetServiceAccountInfo(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_GetServiceAccountInfo_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).GetServiceAccountInfo(ctx, req.(*GetServiceAccountInfoRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_UpdateServiceAccountRole_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateServiceAccountRoleRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).UpdateServiceAccountRole(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_UpdateServiceAccountRole_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).UpdateServiceAccountRole(ctx, req.(*UpdateServiceAccountRoleRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_DeleteServiceAccount_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteServiceAccountRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).DeleteServiceAccount(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_DeleteServiceAccount_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).DeleteServiceAccount(ctx, req.(*DeleteServiceAccountRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_CreateServiceAccountKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(CreateServiceAccountKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).CreateServiceAccountKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_CreateServiceAccountKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).CreateServiceAccountKey(ctx, req.(*CreateServiceAccountKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_DeleteServiceAccountKey_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(DeleteServiceAccountKeyRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).DeleteServiceAccountKey(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_DeleteServiceAccountKey_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).DeleteServiceAccountKey(ctx, req.(*DeleteServiceAccountKeyRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_UpdateServiceAccountKeyStatus_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(UpdateServiceAccountKeyStatusRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).UpdateServiceAccountKeyStatus(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_UpdateServiceAccountKeyStatus_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).UpdateServiceAccountKeyStatus(ctx, req.(*UpdateServiceAccountKeyStatusRequest))
	}
	return interceptor(ctx, in, info, handler)
}

func _API_ListAuditLogs_Handler(srv interface{}, ctx context.Context, dec func(interface{}) error, interceptor grpc.UnaryServerInterceptor) (interface{}, error) {
	in := new(ListAuditLogsRequest)
	if err := dec(in); err != nil {
		return nil, err
	}
	if interceptor == nil {
		return srv.(APIServer).ListAuditLogs(ctx, in)
	}
	info := &grpc.UnaryServerInfo{
		Server:     srv,
		FullMethod: API_ListAuditLogs_FullMethodName,
	}
	handler := func(ctx context.Context, req interface{}) (interface{}, error) {
		return srv.(APIServer).ListAuditLogs(ctx, req.(*ListAuditLogsRequest))
	}
	return interceptor(ctx, in, info, handler)
}

// API_ServiceDesc is the grpc.ServiceDesc for API service.
// It's only intended for direct use with grpc.RegisterService,
// and not to be introspected or modified (even as a copy)
var API_ServiceDesc = grpc.ServiceDesc{
	ServiceName: "com.spirl.api.v1.access.API",
	HandlerType: (*APIServer)(nil),
	Methods: []grpc.MethodDesc{
		{
			MethodName: "ListOrgRoles",
			Handler:    _API_ListOrgRoles_Handler,
		},
		{
			MethodName: "ListUsers",
			Handler:    _API_ListUsers_Handler,
		},
		{
			MethodName: "UpdateUserRole",
			Handler:    _API_UpdateUserRole_Handler,
		},
		{
			MethodName: "DeleteUser",
			Handler:    _API_DeleteUser_Handler,
		},
		{
			MethodName: "CreateUserInvitation",
			Handler:    _API_CreateUserInvitation_Handler,
		},
		{
			MethodName: "RenewUserInvitation",
			Handler:    _API_RenewUserInvitation_Handler,
		},
		{
			MethodName: "DeleteUserInvitation",
			Handler:    _API_DeleteUserInvitation_Handler,
		},
		{
			MethodName: "ListUserInvitations",
			Handler:    _API_ListUserInvitations_Handler,
		},
		{
			MethodName: "CreateServiceAccount",
			Handler:    _API_CreateServiceAccount_Handler,
		},
		{
			MethodName: "ListServiceAccounts",
			Handler:    _API_ListServiceAccounts_Handler,
		},
		{
			MethodName: "GetServiceAccountInfo",
			Handler:    _API_GetServiceAccountInfo_Handler,
		},
		{
			MethodName: "UpdateServiceAccountRole",
			Handler:    _API_UpdateServiceAccountRole_Handler,
		},
		{
			MethodName: "DeleteServiceAccount",
			Handler:    _API_DeleteServiceAccount_Handler,
		},
		{
			MethodName: "CreateServiceAccountKey",
			Handler:    _API_CreateServiceAccountKey_Handler,
		},
		{
			MethodName: "DeleteServiceAccountKey",
			Handler:    _API_DeleteServiceAccountKey_Handler,
		},
		{
			MethodName: "UpdateServiceAccountKeyStatus",
			Handler:    _API_UpdateServiceAccountKeyStatus_Handler,
		},
		{
			MethodName: "ListAuditLogs",
			Handler:    _API_ListAuditLogs_Handler,
		},
	},
	Streams:  []grpc.StreamDesc{},
	Metadata: "api/v1/accessapi/api.proto",
}
