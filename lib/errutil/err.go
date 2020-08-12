// Copyright 2019 Google LLC
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

// Package errutil contains helpers for error.
package errutil

import (
	"strconv"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
	edpb "google.golang.org/genproto/googleapis/rpc/errdetails" /* copybara-comment */
)

// NewError returns a Status error with path or name field.
func NewError(code codes.Code, name string, msg string) error {
	s := status.New(code, msg)
	r := &edpb.ResourceInfo{ResourceName: name, Description: msg}
	es, err := s.WithDetails(r)
	if err == nil {
		return es.Err()
	}
	return s.Err()
}

// NewIndexError returns a Status error with an additional index metadata field.
func NewIndexError(code codes.Code, name string, index int, msg string) error {
	s := status.New(code, msg)
	r := &edpb.ResourceInfo{ResourceName: name, Description: msg}
	e := &edpb.ErrorInfo{Metadata: map[string]string{"index": strconv.Itoa(index)}}
	es, err := s.WithDetails(r, e)
	if err == nil {
		return es.Err()
	}
	return s.Err()
}

// WithErrorReason add error reason to status error.
func WithErrorReason(reason string, err error) error {
	return WithMetadata("reason", reason, err)
}

// ErrorReason find error reason attached in status error.
func ErrorReason(err error) string {
	s, ok := status.FromError(err)
	if !ok {
		glog.Error("not a status error")
		return ""
	}
	for _, d := range s.Details() {
		switch v := d.(type) {
		case *edpb.ErrorInfo:
			return v.GetMetadata()["reason"]
		}
	}
	return ""
}

// ErrorPath combines multiple path elements into one string path.
func ErrorPath(list ...string) string {
	return strings.Join(list, "/")
}

// WithMetadata attaches or replaces a key/value pair to ErrorInfo detail status error.
func WithMetadata(key, value string, err error) error {
	s, ok := status.FromError(err)
	if !ok {
		glog.Error("not a status error")
		return err
	}
	p := s.Proto()
	info := &edpb.ErrorInfo{}
	details := p.GetDetails()
	for i, d := range details {
		if d.MessageIs(info) {
			if err := ptypes.UnmarshalAny(d, info); err != nil {
				glog.Errorf("ptypes.UnmarshalAny() failed: %v", err)
				continue
			}
			m := info.GetMetadata()
			m[key] = value
			out, err := ptypes.MarshalAny(info)
			if err != nil {
				glog.Errorf("ptypes.MarshalAny() failed: %v", err)
				continue
			}
			details[i] = out
			return status.FromProto(p).Err()
		}
	}
	s, derr := s.WithDetails(&edpb.ErrorInfo{Metadata: map[string]string{key: value}})
	if derr != nil {
		glog.Errorf("status.WithDetails() failed: %v", derr)
		return err
	}
	return s.Err()
}
