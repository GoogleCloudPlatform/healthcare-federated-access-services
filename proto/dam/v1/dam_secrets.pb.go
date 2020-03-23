// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Code generated by protoc-gen-go. DO NOT EDIT.
// source: proto/dam/v1/dam_secrets.proto

// Package dam provides protocol buffer versions of the DAM API, allowing
// end points to receive requests and returns responses using these messages.
package v1

import (
	fmt "fmt"
	math "math"

	proto "github.com/golang/protobuf/proto"
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

type DamSecrets struct {
	Version              string                          `protobuf:"bytes,1,opt,name=version,proto3" json:"version,omitempty"`
	Revision             int64                           `protobuf:"varint,2,opt,name=revision,proto3" json:"revision,omitempty"`
	CommitTime           float64                         `protobuf:"fixed64,3,opt,name=commit_time,json=commitTime,proto3" json:"commit_time,omitempty"`
	ClientSecrets        map[string]string               `protobuf:"bytes,4,rep,name=client_secrets,json=clientSecrets,proto3" json:"client_secrets,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	PublicTokenKeys      map[string]string               `protobuf:"bytes,5,rep,name=public_token_keys,json=publicTokenKeys,proto3" json:"public_token_keys,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	BrokerSecrets        map[string]string               `protobuf:"bytes,7,rep,name=broker_secrets,json=brokerSecrets,proto3" json:"broker_secrets,omitempty" protobuf_key:"bytes,1,opt,name=key,proto3" protobuf_val:"bytes,2,opt,name=value,proto3"`
	GatekeeperTokenKeys  *DamSecrets_GatekeeperTokenKeys `protobuf:"bytes,6,opt,name=gatekeeper_token_keys,json=gatekeeperTokenKeys,proto3" json:"gatekeeper_token_keys,omitempty"`
	XXX_NoUnkeyedLiteral struct{}                        `json:"-"`
	XXX_unrecognized     []byte                          `json:"-"`
	XXX_sizecache        int32                           `json:"-"`
}

func (m *DamSecrets) Reset()         { *m = DamSecrets{} }
func (m *DamSecrets) String() string { return proto.CompactTextString(m) }
func (*DamSecrets) ProtoMessage()    {}
func (*DamSecrets) Descriptor() ([]byte, []int) {
	return fileDescriptor_e301ca973d5091dc, []int{0}
}

func (m *DamSecrets) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DamSecrets.Unmarshal(m, b)
}
func (m *DamSecrets) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DamSecrets.Marshal(b, m, deterministic)
}
func (m *DamSecrets) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DamSecrets.Merge(m, src)
}
func (m *DamSecrets) XXX_Size() int {
	return xxx_messageInfo_DamSecrets.Size(m)
}
func (m *DamSecrets) XXX_DiscardUnknown() {
	xxx_messageInfo_DamSecrets.DiscardUnknown(m)
}

var xxx_messageInfo_DamSecrets proto.InternalMessageInfo

func (m *DamSecrets) GetVersion() string {
	if m != nil {
		return m.Version
	}
	return ""
}

func (m *DamSecrets) GetRevision() int64 {
	if m != nil {
		return m.Revision
	}
	return 0
}

func (m *DamSecrets) GetCommitTime() float64 {
	if m != nil {
		return m.CommitTime
	}
	return 0
}

func (m *DamSecrets) GetClientSecrets() map[string]string {
	if m != nil {
		return m.ClientSecrets
	}
	return nil
}

func (m *DamSecrets) GetPublicTokenKeys() map[string]string {
	if m != nil {
		return m.PublicTokenKeys
	}
	return nil
}

func (m *DamSecrets) GetBrokerSecrets() map[string]string {
	if m != nil {
		return m.BrokerSecrets
	}
	return nil
}

func (m *DamSecrets) GetGatekeeperTokenKeys() *DamSecrets_GatekeeperTokenKeys {
	if m != nil {
		return m.GatekeeperTokenKeys
	}
	return nil
}

type DamSecrets_GatekeeperTokenKeys struct {
	PrivateKey           string   `protobuf:"bytes,1,opt,name=private_key,json=privateKey,proto3" json:"private_key,omitempty"`
	PublicKey            string   `protobuf:"bytes,2,opt,name=public_key,json=publicKey,proto3" json:"public_key,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *DamSecrets_GatekeeperTokenKeys) Reset()         { *m = DamSecrets_GatekeeperTokenKeys{} }
func (m *DamSecrets_GatekeeperTokenKeys) String() string { return proto.CompactTextString(m) }
func (*DamSecrets_GatekeeperTokenKeys) ProtoMessage()    {}
func (*DamSecrets_GatekeeperTokenKeys) Descriptor() ([]byte, []int) {
	return fileDescriptor_e301ca973d5091dc, []int{0, 3}
}

func (m *DamSecrets_GatekeeperTokenKeys) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_DamSecrets_GatekeeperTokenKeys.Unmarshal(m, b)
}
func (m *DamSecrets_GatekeeperTokenKeys) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_DamSecrets_GatekeeperTokenKeys.Marshal(b, m, deterministic)
}
func (m *DamSecrets_GatekeeperTokenKeys) XXX_Merge(src proto.Message) {
	xxx_messageInfo_DamSecrets_GatekeeperTokenKeys.Merge(m, src)
}
func (m *DamSecrets_GatekeeperTokenKeys) XXX_Size() int {
	return xxx_messageInfo_DamSecrets_GatekeeperTokenKeys.Size(m)
}
func (m *DamSecrets_GatekeeperTokenKeys) XXX_DiscardUnknown() {
	xxx_messageInfo_DamSecrets_GatekeeperTokenKeys.DiscardUnknown(m)
}

var xxx_messageInfo_DamSecrets_GatekeeperTokenKeys proto.InternalMessageInfo

func (m *DamSecrets_GatekeeperTokenKeys) GetPrivateKey() string {
	if m != nil {
		return m.PrivateKey
	}
	return ""
}

func (m *DamSecrets_GatekeeperTokenKeys) GetPublicKey() string {
	if m != nil {
		return m.PublicKey
	}
	return ""
}

func init() {
	proto.RegisterType((*DamSecrets)(nil), "dam.v1.DamSecrets")
	proto.RegisterMapType((map[string]string)(nil), "dam.v1.DamSecrets.BrokerSecretsEntry")
	proto.RegisterMapType((map[string]string)(nil), "dam.v1.DamSecrets.ClientSecretsEntry")
	proto.RegisterMapType((map[string]string)(nil), "dam.v1.DamSecrets.PublicTokenKeysEntry")
	proto.RegisterType((*DamSecrets_GatekeeperTokenKeys)(nil), "dam.v1.DamSecrets.GatekeeperTokenKeys")
}

func init() {
	proto.RegisterFile("proto/dam/v1/dam_secrets.proto", fileDescriptor_e301ca973d5091dc)
}

var fileDescriptor_e301ca973d5091dc = []byte{
	// 421 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x94, 0x93, 0x4f, 0x6f, 0x9b, 0x40,
	0x10, 0xc5, 0x45, 0x5c, 0x3b, 0xf5, 0x58, 0xfd, 0xb7, 0x49, 0x25, 0x64, 0xa9, 0x2d, 0xaa, 0xd4,
	0x96, 0x8b, 0x41, 0x49, 0x2f, 0x55, 0x4f, 0x91, 0xd3, 0x2a, 0x07, 0xf7, 0x60, 0x91, 0xf4, 0x92,
	0x0b, 0x5a, 0x96, 0x89, 0xbd, 0x82, 0xf5, 0xa2, 0xdd, 0x35, 0x12, 0x9f, 0xb2, 0x5f, 0xa9, 0x62,
	0x21, 0x84, 0xc8, 0xe4, 0x90, 0x93, 0xfd, 0xde, 0x3c, 0x3d, 0xfd, 0x98, 0x01, 0xf8, 0x58, 0x28,
	0x69, 0x64, 0x98, 0x52, 0x11, 0x96, 0x67, 0xf5, 0x4f, 0xac, 0x91, 0x29, 0x34, 0x3a, 0xb0, 0x03,
	0x32, 0x49, 0xa9, 0x08, 0xca, 0xb3, 0xcf, 0xff, 0xc6, 0x00, 0xbf, 0xa8, 0xb8, 0x6e, 0x86, 0xc4,
	0x85, 0xe3, 0x12, 0x95, 0xe6, 0x72, 0xe7, 0x3a, 0x9e, 0xe3, 0x4f, 0xa3, 0x7b, 0x49, 0xe6, 0xf0,
	0x52, 0x61, 0xc9, 0xed, 0xe8, 0xc8, 0x73, 0xfc, 0x51, 0xd4, 0x69, 0xf2, 0x09, 0x66, 0x4c, 0x0a,
	0xc1, 0x4d, 0x6c, 0xb8, 0x40, 0x77, 0xe4, 0x39, 0xbe, 0x13, 0x41, 0x63, 0xdd, 0x70, 0x81, 0xe4,
	0x0f, 0xbc, 0x66, 0x39, 0xc7, 0x9d, 0xb9, 0xa7, 0x70, 0x5f, 0x78, 0x23, 0x7f, 0x76, 0xfe, 0x25,
	0x68, 0x30, 0x82, 0x07, 0x84, 0xe0, 0xd2, 0x06, 0x5b, 0xf5, 0x7b, 0x67, 0x54, 0x15, 0xbd, 0x62,
	0x7d, 0x8f, 0x5c, 0xc3, 0xbb, 0x62, 0x9f, 0xe4, 0x9c, 0xc5, 0x46, 0x66, 0xb8, 0x8b, 0x33, 0xac,
	0xb4, 0x3b, 0xb6, 0x85, 0xdf, 0x06, 0x0a, 0xd7, 0x36, 0x7b, 0x53, 0x47, 0x57, 0x58, 0xb5, 0x95,
	0x6f, 0x8a, 0xc7, 0x6e, 0x8d, 0x98, 0x28, 0x99, 0xa1, 0xea, 0x10, 0x8f, 0x9f, 0x44, 0x5c, 0xda,
	0xe0, 0x63, 0xc4, 0xa4, 0xef, 0x91, 0x5b, 0x78, 0xbf, 0xa1, 0x06, 0x33, 0xc4, 0x02, 0x55, 0x1f,
	0x73, 0xe2, 0x39, 0xfe, 0xec, 0xfc, 0xeb, 0x40, 0xe9, 0x55, 0x97, 0xef, 0xa0, 0xa2, 0x93, 0xcd,
	0xa1, 0x39, 0xbf, 0x00, 0x72, 0xb8, 0x23, 0xf2, 0x16, 0x46, 0x19, 0x56, 0xed, 0xd5, 0xea, 0xbf,
	0xe4, 0x14, 0xc6, 0x25, 0xcd, 0xf7, 0x68, 0xcf, 0x35, 0x8d, 0x1a, 0xf1, 0xf3, 0xe8, 0x87, 0x33,
	0x5f, 0xc2, 0xe9, 0xd0, 0x52, 0x9e, 0xd5, 0x71, 0x01, 0xe4, 0x70, 0x0d, 0xcf, 0x6a, 0xf8, 0x0b,
	0x27, 0x03, 0xcf, 0x5c, 0xbf, 0x4c, 0x85, 0xe2, 0x25, 0x35, 0x18, 0x3f, 0x54, 0x41, 0x6b, 0xad,
	0xb0, 0x22, 0x1f, 0x00, 0xda, 0xf3, 0xd7, 0xf3, 0xa6, 0x76, 0xda, 0x38, 0x2b, 0xac, 0x96, 0xd1,
	0xed, 0x7a, 0xc3, 0xcd, 0x76, 0x9f, 0x04, 0x4c, 0x8a, 0xf0, 0x4a, 0xca, 0x4d, 0x8e, 0x97, 0xb9,
	0xdc, 0xa7, 0xeb, 0x9c, 0x9a, 0x3b, 0xa9, 0x44, 0xb8, 0x45, 0x9a, 0x9b, 0x2d, 0xa3, 0x0a, 0x17,
	0x77, 0x98, 0xa2, 0xa2, 0x06, 0xd3, 0x05, 0x65, 0x0c, 0xb5, 0x5e, 0x68, 0x54, 0x25, 0x67, 0xa8,
	0xc3, 0xfe, 0xf7, 0x93, 0x4c, 0xac, 0xfa, 0xfe, 0x3f, 0x00, 0x00, 0xff, 0xff, 0x20, 0x9a, 0x1f,
	0x39, 0x56, 0x03, 0x00, 0x00,
}
