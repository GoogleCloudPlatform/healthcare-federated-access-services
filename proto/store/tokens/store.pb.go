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
// versions:
// 	protoc-gen-go v1.33.0
// 	protoc        v5.26.1
// source: proto/store/tokens/store.proto

// Package tokens provides object in storage for tokens.

package tokens

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

// PendingDeleteToken stores delete_time for the pending delete token. Use the
// token id as the key of the entry.
type PendingDeleteToken struct {
	state         protoimpl.MessageState
	sizeCache     protoimpl.SizeCache
	unknownFields protoimpl.UnknownFields

	// timestamp of user request delete the token.
	DeleteTime int64 `protobuf:"varint,1,opt,name=delete_time,json=deleteTime,proto3" json:"delete_time,omitempty"`
}

func (x *PendingDeleteToken) Reset() {
	*x = PendingDeleteToken{}
	if protoimpl.UnsafeEnabled {
		mi := &file_proto_store_tokens_store_proto_msgTypes[0]
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		ms.StoreMessageInfo(mi)
	}
}

func (x *PendingDeleteToken) String() string {
	return protoimpl.X.MessageStringOf(x)
}

func (*PendingDeleteToken) ProtoMessage() {}

func (x *PendingDeleteToken) ProtoReflect() protoreflect.Message {
	mi := &file_proto_store_tokens_store_proto_msgTypes[0]
	if protoimpl.UnsafeEnabled && x != nil {
		ms := protoimpl.X.MessageStateOf(protoimpl.Pointer(x))
		if ms.LoadMessageInfo() == nil {
			ms.StoreMessageInfo(mi)
		}
		return ms
	}
	return mi.MessageOf(x)
}

// Deprecated: Use PendingDeleteToken.ProtoReflect.Descriptor instead.
func (*PendingDeleteToken) Descriptor() ([]byte, []int) {
	return file_proto_store_tokens_store_proto_rawDescGZIP(), []int{0}
}

func (x *PendingDeleteToken) GetDeleteTime() int64 {
	if x != nil {
		return x.DeleteTime
	}
	return 0
}

var File_proto_store_tokens_store_proto protoreflect.FileDescriptor

var file_proto_store_tokens_store_proto_rawDesc = []byte{
	0x0a, 0x1e, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2f, 0x74, 0x6f,
	0x6b, 0x65, 0x6e, 0x73, 0x2f, 0x73, 0x74, 0x6f, 0x72, 0x65, 0x2e, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x12, 0x06, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x22, 0x35, 0x0a, 0x12, 0x50, 0x65, 0x6e, 0x64,
	0x69, 0x6e, 0x67, 0x44, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x54, 0x6f, 0x6b, 0x65, 0x6e, 0x12, 0x1f,
	0x0a, 0x0b, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x5f, 0x74, 0x69, 0x6d, 0x65, 0x18, 0x01, 0x20,
	0x01, 0x28, 0x03, 0x52, 0x0a, 0x64, 0x65, 0x6c, 0x65, 0x74, 0x65, 0x54, 0x69, 0x6d, 0x65, 0x42,
	0x58, 0x5a, 0x56, 0x67, 0x69, 0x74, 0x68, 0x75, 0x62, 0x2e, 0x63, 0x6f, 0x6d, 0x2f, 0x47, 0x6f,
	0x6f, 0x67, 0x6c, 0x65, 0x43, 0x6c, 0x6f, 0x75, 0x64, 0x50, 0x6c, 0x61, 0x74, 0x66, 0x6f, 0x72,
	0x6d, 0x2f, 0x68, 0x65, 0x61, 0x6c, 0x74, 0x68, 0x63, 0x61, 0x72, 0x65, 0x2d, 0x66, 0x65, 0x64,
	0x65, 0x72, 0x61, 0x74, 0x65, 0x64, 0x2d, 0x61, 0x63, 0x63, 0x65, 0x73, 0x73, 0x2d, 0x73, 0x65,
	0x72, 0x76, 0x69, 0x63, 0x65, 0x73, 0x2f, 0x70, 0x72, 0x6f, 0x74, 0x6f, 0x2f, 0x73, 0x74, 0x6f,
	0x72, 0x65, 0x2f, 0x74, 0x6f, 0x6b, 0x65, 0x6e, 0x73, 0x62, 0x06, 0x70, 0x72, 0x6f, 0x74, 0x6f,
	0x33,
}

var (
	file_proto_store_tokens_store_proto_rawDescOnce sync.Once
	file_proto_store_tokens_store_proto_rawDescData = file_proto_store_tokens_store_proto_rawDesc
)

func file_proto_store_tokens_store_proto_rawDescGZIP() []byte {
	file_proto_store_tokens_store_proto_rawDescOnce.Do(func() {
		file_proto_store_tokens_store_proto_rawDescData = protoimpl.X.CompressGZIP(file_proto_store_tokens_store_proto_rawDescData)
	})
	return file_proto_store_tokens_store_proto_rawDescData
}

var file_proto_store_tokens_store_proto_msgTypes = make([]protoimpl.MessageInfo, 1)
var file_proto_store_tokens_store_proto_goTypes = []interface{}{
	(*PendingDeleteToken)(nil), // 0: tokens.PendingDeleteToken
}
var file_proto_store_tokens_store_proto_depIdxs = []int32{
	0, // [0:0] is the sub-list for method output_type
	0, // [0:0] is the sub-list for method input_type
	0, // [0:0] is the sub-list for extension type_name
	0, // [0:0] is the sub-list for extension extendee
	0, // [0:0] is the sub-list for field type_name
}

func init() { file_proto_store_tokens_store_proto_init() }
func file_proto_store_tokens_store_proto_init() {
	if File_proto_store_tokens_store_proto != nil {
		return
	}
	if !protoimpl.UnsafeEnabled {
		file_proto_store_tokens_store_proto_msgTypes[0].Exporter = func(v interface{}, i int) interface{} {
			switch v := v.(*PendingDeleteToken); i {
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
	type x struct{}
	out := protoimpl.TypeBuilder{
		File: protoimpl.DescBuilder{
			GoPackagePath: reflect.TypeOf(x{}).PkgPath(),
			RawDescriptor: file_proto_store_tokens_store_proto_rawDesc,
			NumEnums:      0,
			NumMessages:   1,
			NumExtensions: 0,
			NumServices:   0,
		},
		GoTypes:           file_proto_store_tokens_store_proto_goTypes,
		DependencyIndexes: file_proto_store_tokens_store_proto_depIdxs,
		MessageInfos:      file_proto_store_tokens_store_proto_msgTypes,
	}.Build()
	File_proto_store_tokens_store_proto = out.File
	file_proto_store_tokens_store_proto_rawDesc = nil
	file_proto_store_tokens_store_proto_goTypes = nil
	file_proto_store_tokens_store_proto_depIdxs = nil
}
