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

package errutil

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */

	edpb "google.golang.org/genproto/googleapis/rpc/errdetails" /* copybara-comment */
)

func TestNewIndexError(t *testing.T) {
	err := NewIndexError(codes.InvalidArgument, "name", 3, "this is an error message")
	want := []interface{}{
		&edpb.ResourceInfo{ResourceName: "name", Description: "this is an error message"},
		&edpb.ErrorInfo{Metadata: map[string]string{"index": "3"}},
	}

	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("FromError() failed")
	}
	if d := cmp.Diff(want, s.Details(), protocmp.Transform()); len(d) > 0 {
		t.Errorf("s.Details (-want, +got): %s", d)
	}
}

func TestWithErrorReason(t *testing.T) {
	errReason := "reason"

	err := WithErrorReason(errReason, status.Error(codes.Internal, "this is a error"))

	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("status.FromError(%v) failed", err)
	}

	want := []interface{}{
		&edpb.ErrorInfo{Metadata: map[string]string{"reason": errReason}},
	}

	if d := cmp.Diff(want, s.Details(), protocmp.Transform()); len(d) > 0 {
		t.Errorf("s.Details() (-want, +got): %s", d)
	}
}

func TestErrorReason(t *testing.T) {
	errReason := "reason"

	err := WithErrorReason(errReason, status.Error(codes.Internal, "this is a error"))

	got := ErrorReason(err)
	if got != errReason {
		t.Errorf("ErrorReason() =%s want %s", got, errReason)
	}
}

func TestErrorReason_NotStatusErr(t *testing.T) {
	errReason := "reason"

	err := WithErrorReason(errReason, fmt.Errorf("this is a error"))

	got := ErrorReason(err)
	if len(got) > 0 {
		t.Errorf("ErrorReason() = %s want \"\"", got)
	}
}

func TestErrorPath(t *testing.T) {
	got := ErrorPath("a", "b", "c")
	want := "a/b/c"
	if got != want {
		t.Errorf("mismatch: got %q, want %q", got, want)
	}
}

func TestWithMetadata(t *testing.T) {
	meta := map[string]string{
		"a": "1",
		"b": "2",
		"c": "3",
	}

	err := status.Error(codes.Internal, "this is a error")
	for k, v := range meta {
		err = WithMetadata(k, v, err)
	}

	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("status.FromError(%v) failed", err)
	}

	want := []interface{}{
		&edpb.ErrorInfo{Metadata: meta},
	}

	if d := cmp.Diff(want, s.Details(), protocmp.Transform()); len(d) > 0 {
		t.Errorf("s.Details() (-want, +got): %s", d)
	}
}
