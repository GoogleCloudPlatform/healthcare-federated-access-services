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

func TestWithErrorType(t *testing.T) {
	errType := "type"

	err := WithErrorType(errType, status.Error(codes.Internal, "this is a error"))

	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("status.FromError(%v) failed", err)
	}

	want := []interface{}{
		&edpb.ErrorInfo{Type: errType},
	}

	if d := cmp.Diff(want, s.Details(), protocmp.Transform()); len(d) > 0 {
		t.Errorf("s.Details() (-want, +got): %s", d)
	}
}

func TestErrorType(t *testing.T) {
	errType := "type"

	err := WithErrorType(errType, status.Error(codes.Internal, "this is a error"))

	got := ErrorType(err)
	if got != errType {
		t.Errorf("ErrorType() =%s want %s", got, errType)
	}
}

func TestErrorType_NotStatusErr(t *testing.T) {
	errType := "type"

	err := fmt.Errorf("this is a error")
	err = WithErrorType(errType, err)

	got := ErrorType(err)
	if got != "" {
		t.Errorf("ErrorType() =%s want \"\"", got)
	}
}
