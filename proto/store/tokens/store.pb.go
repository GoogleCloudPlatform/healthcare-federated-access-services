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
// source: proto/store/tokens/store.proto

// Package tokens provides object in storage for tokens.
package tokens

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

// PendingDeleteToken stores delete_time for the pending delete token. Use the
// token id as the key of the entry.
type PendingDeleteToken struct {
	// timestamp of user request delete the token.
	DeleteTime           int64    `protobuf:"varint,1,opt,name=delete_time,json=deleteTime,proto3" json:"delete_time,omitempty"`
	XXX_NoUnkeyedLiteral struct{} `json:"-"`
	XXX_unrecognized     []byte   `json:"-"`
	XXX_sizecache        int32    `json:"-"`
}

func (m *PendingDeleteToken) Reset()         { *m = PendingDeleteToken{} }
func (m *PendingDeleteToken) String() string { return proto.CompactTextString(m) }
func (*PendingDeleteToken) ProtoMessage()    {}
func (*PendingDeleteToken) Descriptor() ([]byte, []int) {
	return fileDescriptor_1acf45993fe37728, []int{0}
}

func (m *PendingDeleteToken) XXX_Unmarshal(b []byte) error {
	return xxx_messageInfo_PendingDeleteToken.Unmarshal(m, b)
}
func (m *PendingDeleteToken) XXX_Marshal(b []byte, deterministic bool) ([]byte, error) {
	return xxx_messageInfo_PendingDeleteToken.Marshal(b, m, deterministic)
}
func (m *PendingDeleteToken) XXX_Merge(src proto.Message) {
	xxx_messageInfo_PendingDeleteToken.Merge(m, src)
}
func (m *PendingDeleteToken) XXX_Size() int {
	return xxx_messageInfo_PendingDeleteToken.Size(m)
}
func (m *PendingDeleteToken) XXX_DiscardUnknown() {
	xxx_messageInfo_PendingDeleteToken.DiscardUnknown(m)
}

var xxx_messageInfo_PendingDeleteToken proto.InternalMessageInfo

func (m *PendingDeleteToken) GetDeleteTime() int64 {
	if m != nil {
		return m.DeleteTime
	}
	return 0
}

func init() {
	proto.RegisterType((*PendingDeleteToken)(nil), "tokens.PendingDeleteToken")
}

func init() {
	proto.RegisterFile("proto/store/tokens/store.proto", fileDescriptor_1acf45993fe37728)
}

var fileDescriptor_1acf45993fe37728 = []byte{
	// 171 bytes of a gzipped FileDescriptorProto
	0x1f, 0x8b, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0xff, 0x64, 0xce, 0xb1, 0xaa, 0xc2, 0x30,
	0x18, 0xc5, 0x71, 0xca, 0x85, 0x0e, 0xb9, 0x5b, 0x27, 0x27, 0x15, 0x27, 0x97, 0x36, 0x83, 0xf8,
	0x02, 0x2a, 0xb8, 0x16, 0x29, 0x22, 0x2e, 0x92, 0x26, 0xa7, 0x6d, 0x30, 0xe9, 0x27, 0xc9, 0x57,
	0x9f, 0x5f, 0x6c, 0x46, 0xc7, 0xff, 0xef, 0x2c, 0x47, 0x2c, 0x5f, 0x81, 0x98, 0x64, 0x64, 0x0a,
	0x90, 0x4c, 0x4f, 0x8c, 0x31, 0x45, 0x35, 0x0f, 0x45, 0x9e, 0x6c, 0xb3, 0x17, 0x45, 0x8d, 0xd1,
	0xd8, 0xb1, 0x3f, 0xc1, 0x81, 0xd1, 0x7c, 0xb9, 0x58, 0x89, 0x7f, 0x33, 0xe7, 0x83, 0xad, 0xc7,
	0x22, 0x5b, 0x67, 0xdb, 0xbf, 0x8b, 0x48, 0xd4, 0x58, 0x8f, 0xc3, 0xed, 0x7e, 0xed, 0x2d, 0x0f,
	0x53, 0x5b, 0x69, 0xf2, 0xf2, 0x4c, 0xd4, 0x3b, 0x1c, 0x1d, 0x4d, 0xa6, 0x76, 0x8a, 0x3b, 0x0a,
	0x5e, 0x0e, 0x50, 0x8e, 0x07, 0xad, 0x02, 0xca, 0x0e, 0x06, 0x41, 0x31, 0x4c, 0xa9, 0xb4, 0x46,
	0x8c, 0x65, 0x44, 0x78, 0x5b, 0x8d, 0x28, 0x7f, 0x4f, 0xb6, 0xf9, 0x6c, 0xbb, 0x4f, 0x00, 0x00,
	0x00, 0xff, 0xff, 0xd7, 0x17, 0x1f, 0x2e, 0xc1, 0x00, 0x00, 0x00,
}
