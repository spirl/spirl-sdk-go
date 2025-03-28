// Code generated by protoc-gen-go. DO NOT EDIT.
// versions:
// 	protoc-gen-go v1.34.2
// 	protoc        (unknown)
// source: api/v1/providerattestationapi/api.proto

package providerattestationapi

import (
	protoreflect "google.golang.org/protobuf/reflect/protoreflect"
	protoimpl "google.golang.org/protobuf/runtime/protoimpl"
	reflect "reflect"
	sync "sync"
)

const (
	// Verify that this generated code is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(20 - protoimpl.MinVersion)
	// Verify that runtime/protoimpl is sufficiently up-to-date.
	_ = protoimpl.EnforceVersion(protoimpl.MaxVersion - 20)
)

type CreateConfigRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Required. The name of the config.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
	// Required. The specific configuration for the provider.
	//
	// Types that are assignable to Config:
	//
	//	*CreateConfigRequest_Aws
	Config isCreateConfigRequest_Config `protobuf_oneof:"config"`
}

func (x *CreateConfigRequest) Reset() {
	*x = CreateConfigRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateConfigRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateConfigRequest) ProtoMessage() {}

func (x *CreateConfigRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateConfigRequest.ProtoReflect.Descriptor instead.
func (*CreateConfigRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{0}
}

func (x *CreateConfigRequest) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *CreateConfigRequest) GetConfig() isCreateConfigRequest_Config {
	if m != nil {
		return m.Config
	}
	return nil
}

func (x *CreateConfigRequest) GetAws() *AWSConfig {
	if x, ok := x.GetConfig().(*CreateConfigRequest_Aws); ok {
		return x.Aws
	}
	return nil
}

type isCreateConfigRequest_Config interface {
	isCreateConfigRequest_Config()
}

type CreateConfigRequest_Aws struct {
	Aws *AWSConfig `protobuf:"bytes,2,opt,name=aws,proto3,oneof"`
}

func (*CreateConfigRequest_Aws) isCreateConfigRequest_Config() {}

type CreateConfigResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Config *Config `protobuf:"bytes,1,opt,name=config,proto3" json:"config,omitempty"`
}

func (x *CreateConfigResponse) Reset() {
	*x = CreateConfigResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[1]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *CreateConfigResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*CreateConfigResponse) ProtoMessage() {}

func (x *CreateConfigResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[1]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use CreateConfigResponse.ProtoReflect.Descriptor instead.
func (*CreateConfigResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{1}
}

func (x *CreateConfigResponse) GetConfig() *Config {
	if x != nil {
		return x.Config
	}
	return nil
}

type ListConfigsRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Optional. If provided, the filter to list the configs.
	Filter *ConfigFilter `protobuf:"bytes,1,opt,name=filter,proto3" json:"filter,omitempty"`
}

func (x *ListConfigsRequest) Reset() {
	*x = ListConfigsRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[2]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListConfigsRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListConfigsRequest) ProtoMessage() {}

func (x *ListConfigsRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[2]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListConfigsRequest.ProtoReflect.Descriptor instead.
func (*ListConfigsRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{2}
}

func (x *ListConfigsRequest) GetFilter() *ConfigFilter {
	if x != nil {
		return x.Filter
	}
	return nil
}

type ListConfigsResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Configs []*Config `protobuf:"bytes,1,rep,name=configs,proto3" json:"configs,omitempty"`
}

func (x *ListConfigsResponse) Reset() {
	*x = ListConfigsResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[3]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ListConfigsResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ListConfigsResponse) ProtoMessage() {}

func (x *ListConfigsResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[3]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ListConfigsResponse.ProtoReflect.Descriptor instead.
func (*ListConfigsResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{3}
}

func (x *ListConfigsResponse) GetConfigs() []*Config {
	if x != nil {
		return x.Configs
	}
	return nil
}

type GetConfigRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Required. The id of the config.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *GetConfigRequest) Reset() {
	*x = GetConfigRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[4]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetConfigRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConfigRequest) ProtoMessage() {}

func (x *GetConfigRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[4]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConfigRequest.ProtoReflect.Descriptor instead.
func (*GetConfigRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{4}
}

func (x *GetConfigRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type GetConfigResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Config *Config `protobuf:"bytes,1,opt,name=config,proto3" json:"config,omitempty"`
}

func (x *GetConfigResponse) Reset() {
	*x = GetConfigResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[5]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *GetConfigResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*GetConfigResponse) ProtoMessage() {}

func (x *GetConfigResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[5]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use GetConfigResponse.ProtoReflect.Descriptor instead.
func (*GetConfigResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{5}
}

func (x *GetConfigResponse) GetConfig() *Config {
	if x != nil {
		return x.Config
	}
	return nil
}

type DeleteConfigRequest struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Required. The ID of the config to be deleted.
	Id string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
}

func (x *DeleteConfigRequest) Reset() {
	*x = DeleteConfigRequest{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[6]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteConfigRequest) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteConfigRequest) ProtoMessage() {}

func (x *DeleteConfigRequest) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[6]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteConfigRequest.ProtoReflect.Descriptor instead.
func (*DeleteConfigRequest) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{6}
}

func (x *DeleteConfigRequest) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

type DeleteConfigResponse struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields
}

func (x *DeleteConfigResponse) Reset() {
	*x = DeleteConfigResponse{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[7]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *DeleteConfigResponse) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*DeleteConfigResponse) ProtoMessage() {}

func (x *DeleteConfigResponse) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[7]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use DeleteConfigResponse.ProtoReflect.Descriptor instead.
func (*DeleteConfigResponse) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{7}
}

type ConfigFilter struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// Optional. The name of the config.
	Name string `protobuf:"bytes,1,opt,name=name,proto3" json:"name,omitempty"`
}

func (x *ConfigFilter) Reset() {
	*x = ConfigFilter{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[8]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *ConfigFilter) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*ConfigFilter) ProtoMessage() {}

func (x *ConfigFilter) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[8]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use ConfigFilter.ProtoReflect.Descriptor instead.
func (*ConfigFilter) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{8}
}

func (x *ConfigFilter) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

type Config struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	Id   string `protobuf:"bytes,1,opt,name=id,proto3" json:"id,omitempty"`
	Name string `protobuf:"bytes,2,opt,name=name,proto3" json:"name,omitempty"`
	// Types that are assignable to Config:
	//
	//	*Config_Aws
	Config isConfig_Config `protobuf_oneof:"config"`
}

func (x *Config) Reset() {
	*x = Config{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[9]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *Config) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*Config) ProtoMessage() {}

func (x *Config) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[9]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use Config.ProtoReflect.Descriptor instead.
func (*Config) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{9}
}

func (x *Config) GetId() string {
	if x != nil {
		return x.Id
	}
	return ""
}

func (x *Config) GetName() string {
	if x != nil {
		return x.Name
	}
	return ""
}

func (m *Config) GetConfig() isConfig_Config {
	if m != nil {
		return m.Config
	}
	return nil
}

func (x *Config) GetAws() *AWSConfig {
	if x, ok := x.GetConfig().(*Config_Aws); ok {
		return x.Aws
	}
	return nil
}

type isConfig_Config interface {
	isConfig_Config()
}

type Config_Aws struct {
	Aws *AWSConfig `protobuf:"bytes,3,opt,name=aws,proto3,oneof"`
}

func (*Config_Aws) isConfig_Config() {}

type AWSConfig struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// The ARN of the AWS role to assume, this role needs to be provisioned
	// separately, and should have the necessary permissions to query EC2
	// instances.
	RoleArn string `protobuf:"bytes,1,opt,name=role_arn,json=roleArn,proto3" json:"role_arn,omitempty"`
}

func (x *AWSConfig) Reset() {
	*x = AWSConfig{}
	if protoimpl.UnsafeEnabled {
		mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[10]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *AWSConfig) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*AWSConfig) ProtoMessage() {}

func (x *AWSConfig) ProtoReflect() protoreflect.Message {
	mi := &file_api_v1_providerattestationapi_api_proto_msgTypes[10]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use AWSConfig.ProtoReflect.Descriptor instead.
func (*AWSConfig) Descriptor() ([]byte, []int) {
	return file_api_v1_providerattestationapi_api_proto_rawDescGZIP(), []int{10}
}

func (x *AWSConfig) GetRoleArn() string {
	if x != nil {
		return x.RoleArn
	}
	return ""
}

var File_api_v1_providerattestationapi_api_proto protoreflect.FileDescriptor

var file_api_v1_providerattestationapi_api_proto_rawDesc = []byte{
	0x0a, 0x27, 0x61, 0x70, 0x69, 0x2f, 0x76, 0x31, 0x2f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x70, 0x69, 0x2f,
	0x61, 0x70, 0x69, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x12, 0x24, 0x63, 0x6f, 0x6d, 0x2e, 0x73,
	0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x22,
	0x78, 0x0a, 0x13, 0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x43, 0x0a, 0x03, 0x61, 0x77,
	0x73, 0x18, 0x02, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70,
	0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69,
	0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x41,
	0x57, 0x53, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x00, 0x52, 0x03, 0x61, 0x77, 0x73, 0x42,
	0x08, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0x5c, 0x0a, 0x14, 0x43, 0x72, 0x65,
	0x61, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x44, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2c, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0x60, 0x0a, 0x12, 0x4c, 0x69, 0x73, 0x74, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x4a, 0x0a,
	0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x18, 0x01, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x32, 0x2e,
	0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31,
	0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61,
	0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x46, 0x69, 0x6c, 0x74, 0x65,
	0x72, 0x52, 0x06, 0x66, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x22, 0x5d, 0x0a, 0x13, 0x4c, 0x69, 0x73,
	0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65,
	0x12, 0x46, 0x0a, 0x07, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x18, 0x01, 0x20, 0x03, 0x28,
	0x0b, 0x32, 0x2c, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x07, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x22, 0x22, 0x0a, 0x10, 0x47, 0x65, 0x74, 0x43,
	0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e, 0x0a, 0x02,
	0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x59, 0x0a, 0x11,
	0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73,
	0x65, 0x12, 0x44, 0x0a, 0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x18, 0x01, 0x20, 0x01, 0x28,
	0x0b, 0x32, 0x2c, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52,
	0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0x25, 0x0a, 0x13, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x12, 0x0e,
	0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x02, 0x69, 0x64, 0x22, 0x16,
	0x0a, 0x14, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65,
	0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x22, 0x22, 0x0a, 0x0c, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67,
	0x46, 0x69, 0x6c, 0x74, 0x65, 0x72, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x01,
	0x20, 0x01, 0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x22, 0x7b, 0x0a, 0x06, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x12, 0x0e, 0x0a, 0x02, 0x69, 0x64, 0x18, 0x01, 0x20, 0x01, 0x28, 0x09,
	0x52, 0x02, 0x69, 0x64, 0x12, 0x12, 0x0a, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x18, 0x02, 0x20, 0x01,
	0x28, 0x09, 0x52, 0x04, 0x6e, 0x61, 0x6d, 0x65, 0x12, 0x43, 0x0a, 0x03, 0x61, 0x77, 0x73, 0x18,
	0x03, 0x20, 0x01, 0x28, 0x0b, 0x32, 0x2f, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72,
	0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65,
	0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x41, 0x57, 0x53,
	0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x48, 0x00, 0x52, 0x03, 0x61, 0x77, 0x73, 0x42, 0x08, 0x0a,
	0x06, 0x63, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x22, 0x26, 0x0a, 0x09, 0x41, 0x57, 0x53, 0x43, 0x6f,
	0x6e, 0x66, 0x69, 0x67, 0x12, 0x19, 0x0a, 0x08, 0x72, 0x6f, 0x6c, 0x65, 0x5f, 0x61, 0x72, 0x6e,
	0x18, 0x01, 0x20, 0x01, 0x28, 0x09, 0x52, 0x07, 0x72, 0x6f, 0x6c, 0x65, 0x41, 0x72, 0x6e, 0x32,
	0x98, 0x04, 0x0a, 0x03, 0x41, 0x50, 0x49, 0x12, 0x85, 0x01, 0x0a, 0x0c, 0x43, 0x72, 0x65, 0x61,
	0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x12, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73,
	0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76,
	0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e,
	0x43, 0x72, 0x65, 0x61, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x71, 0x75,
	0x65, 0x73, 0x74, 0x1a, 0x3a, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x43, 0x72, 0x65, 0x61, 0x74,
	0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x12,
	0x82, 0x01, 0x0a, 0x0b, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x12,
	0x38, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e,
	0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x73, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e,
	0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f,
	0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x4c, 0x69, 0x73, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x73, 0x52, 0x65, 0x73, 0x70,
	0x6f, 0x6e, 0x73, 0x65, 0x12, 0x7c, 0x0a, 0x09, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69,
	0x67, 0x12, 0x36, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70,
	0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74,
	0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x37, 0x2e, 0x63, 0x6f, 0x6d, 0x2e,
	0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f,
	0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e,
	0x2e, 0x47, 0x65, 0x74, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e,
	0x73, 0x65, 0x12, 0x85, 0x01, 0x0a, 0x0c, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x6f, 0x6e,
	0x66, 0x69, 0x67, 0x12, 0x39, 0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e,
	0x61, 0x70, 0x69, 0x2e, 0x76, 0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61,
	0x74, 0x74, 0x65, 0x73, 0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74,
	0x65, 0x43, 0x6f, 0x6e, 0x66, 0x69, 0x67, 0x52, 0x65, 0x71, 0x75, 0x65, 0x73, 0x74, 0x1a, 0x3a,
	0x2e, 0x63, 0x6f, 0x6d, 0x2e, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2e, 0x61, 0x70, 0x69, 0x2e, 0x76,
	0x31, 0x2e, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73, 0x74,
	0x61, 0x74, 0x69, 0x6f, 0x6e, 0x2e, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x43, 0x6f, 0x6e, 0x66,
	0x69, 0x67, 0x52, 0x65, 0x73, 0x70, 0x6f, 0x6e, 0x73, 0x65, 0x42, 0x3d, 0x5a, 0x3b, 0x67, 0x69,
	0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x73, 0x70, 0x69, 0x72, 0x6c, 0x2f, 0x73,
	0x70, 0x69, 0x72, 0x6c, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x73, 0x2f, 0x61, 0x70, 0x69, 0x2f,
	0x76, 0x31, 0x2f, 0x70, 0x72, 0x6f, 0x76, 0x69, 0x64, 0x65, 0x72, 0x61, 0x74, 0x74, 0x65, 0x73,
	0x74, 0x61, 0x74, 0x69, 0x6f, 0x6e, 0x61, 0x70, 0x69, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_api_v1_providerattestationapi_api_proto_rawDescOnce sync.Once
	file_api_v1_providerattestationapi_api_proto_rawDescData = file_api_v1_providerattestationapi_api_proto_rawDesc
)

func file_api_v1_providerattestationapi_api_proto_rawDescGZIP() []byte {
	file_api_v1_providerattestationapi_api_proto_rawDescOnce.Do(func() {
		file_api_v1_providerattestationapi_api_proto_rawDescData = protoimpl.X.CompressGZIP(file_api_v1_providerattestationapi_api_proto_rawDescData)
	})
	return file_api_v1_providerattestationapi_api_proto_rawDescData
}

var file_api_v1_providerattestationapi_api_proto_msgTypes = make([]protoimpl.MessageInfo, 11)
var file_api_v1_providerattestationapi_api_proto_goTypes = []any{
	(*CreateConfigRequest)(nil),  // 0: com.spirl.api.v1.providerattestation.CreateConfigRequest
	(*CreateConfigResponse)(nil), // 1: com.spirl.api.v1.providerattestation.CreateConfigResponse
	(*ListConfigsRequest)(nil),   // 2: com.spirl.api.v1.providerattestation.ListConfigsRequest
	(*ListConfigsResponse)(nil),  // 3: com.spirl.api.v1.providerattestation.ListConfigsResponse
	(*GetConfigRequest)(nil),     // 4: com.spirl.api.v1.providerattestation.GetConfigRequest
	(*GetConfigResponse)(nil),    // 5: com.spirl.api.v1.providerattestation.GetConfigResponse
	(*DeleteConfigRequest)(nil),  // 6: com.spirl.api.v1.providerattestation.DeleteConfigRequest
	(*DeleteConfigResponse)(nil), // 7: com.spirl.api.v1.providerattestation.DeleteConfigResponse
	(*ConfigFilter)(nil),         // 8: com.spirl.api.v1.providerattestation.ConfigFilter
	(*Config)(nil),               // 9: com.spirl.api.v1.providerattestation.Config
	(*AWSConfig)(nil),            // 10: com.spirl.api.v1.providerattestation.AWSConfig
}
var file_api_v1_providerattestationapi_api_proto_depIdxs = []int32{
	10, // 0: com.spirl.api.v1.providerattestation.CreateConfigRequest.aws:type_name -> com.spirl.api.v1.providerattestation.AWSConfig
	9,  // 1: com.spirl.api.v1.providerattestation.CreateConfigResponse.config:type_name -> com.spirl.api.v1.providerattestation.Config
	8,  // 2: com.spirl.api.v1.providerattestation.ListConfigsRequest.filter:type_name -> com.spirl.api.v1.providerattestation.ConfigFilter
	9,  // 3: com.spirl.api.v1.providerattestation.ListConfigsResponse.configs:type_name -> com.spirl.api.v1.providerattestation.Config
	9,  // 4: com.spirl.api.v1.providerattestation.GetConfigResponse.config:type_name -> com.spirl.api.v1.providerattestation.Config
	10, // 5: com.spirl.api.v1.providerattestation.Config.aws:type_name -> com.spirl.api.v1.providerattestation.AWSConfig
	0,  // 6: com.spirl.api.v1.providerattestation.API.CreateConfig:input_type -> com.spirl.api.v1.providerattestation.CreateConfigRequest
	2,  // 7: com.spirl.api.v1.providerattestation.API.ListConfigs:input_type -> com.spirl.api.v1.providerattestation.ListConfigsRequest
	4,  // 8: com.spirl.api.v1.providerattestation.API.GetConfig:input_type -> com.spirl.api.v1.providerattestation.GetConfigRequest
	6,  // 9: com.spirl.api.v1.providerattestation.API.DeleteConfig:input_type -> com.spirl.api.v1.providerattestation.DeleteConfigRequest
	1,  // 10: com.spirl.api.v1.providerattestation.API.CreateConfig:output_type -> com.spirl.api.v1.providerattestation.CreateConfigResponse
	3,  // 11: com.spirl.api.v1.providerattestation.API.ListConfigs:output_type -> com.spirl.api.v1.providerattestation.ListConfigsResponse
	5,  // 12: com.spirl.api.v1.providerattestation.API.GetConfig:output_type -> com.spirl.api.v1.providerattestation.GetConfigResponse
	7,  // 13: com.spirl.api.v1.providerattestation.API.DeleteConfig:output_type -> com.spirl.api.v1.providerattestation.DeleteConfigResponse
	10, // [10:14] is the sub-list for method output_type
	6,  // [6:10] is the sub-list for method input_type
	6,  // [6:6] is the sub-list for extension type_name
	6,  // [6:6] is the sub-list for extension extendee
	0,  // [0:6] is the sub-list for field type_name
}

func init() { file_api_v1_providerattestationapi_api_proto_init() }
func file_api_v1_providerattestationapi_api_proto_init() {
	if File_api_v1_providerattestationapi_api_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_api_v1_providerattestationapi_api_proto_msgTypes[0].Exporter = func(v any, i int) any {
			switch v := v.(*CreateConfigRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[1].Exporter = func(v any, i int) any {
			switch v := v.(*CreateConfigResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[2].Exporter = func(v any, i int) any {
			switch v := v.(*ListConfigsRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[3].Exporter = func(v any, i int) any {
			switch v := v.(*ListConfigsResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[4].Exporter = func(v any, i int) any {
			switch v := v.(*GetConfigRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[5].Exporter = func(v any, i int) any {
			switch v := v.(*GetConfigResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[6].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteConfigRequest); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[7].Exporter = func(v any, i int) any {
			switch v := v.(*DeleteConfigResponse); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[8].Exporter = func(v any, i int) any {
			switch v := v.(*ConfigFilter); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[9].Exporter = func(v any, i int) any {
			switch v := v.(*Config); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
		file_api_v1_providerattestationapi_api_proto_msgTypes[10].Exporter = func(v any, i int) any {
			switch v := v.(*AWSConfig); i {
			case 0:
				return &v.state
			case 1:
				return &v.sizeCache
			case 2:
				return &v.unknownFields
			default:
				return nil
			}
		}
	}
	file_api_v1_providerattestationapi_api_proto_msgTypes[0].OneofWrappers = []any{
		(*CreateConfigRequest_Aws)(nil),
	}
	file_api_v1_providerattestationapi_api_proto_msgTypes[9].OneofWrappers = []any{
		(*Config_Aws)(nil),
	}
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_api_v1_providerattestationapi_api_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   11,
			NumExtensions: 0,
			NumServices:   1,
		},
		GoTypes:           file_api_v1_providerattestationapi_api_proto_goTypes,
		DependencyIndexes: file_api_v1_providerattestationapi_api_proto_depIdxs,
		MessageInfos:      file_api_v1_providerattestationapi_api_proto_msgTypes,
	}.Build()
	File_api_v1_providerattestationapi_api_proto = out.File
	file_api_v1_providerattestationapi_api_proto_rawDesc = nil
	file_api_v1_providerattestationapi_api_proto_goTypes = nil
	file_api_v1_providerattestationapi_api_proto_depIdxs = nil
}
