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

package dam

import (
	"fmt"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func Test_withRejectedPolicy(t *testing.T) {
	err := withRejectedPolicy(&cpb.RejectedPolicy{Rejections: 1}, status.Error(codes.Internal, "this is a error"))

	s, ok := status.FromError(err)
	if !ok {
		t.Fatalf("status.FromError(%v) failed", err)
	}

	want := []interface{}{
		&cpb.RejectedPolicy{Rejections: 1},
	}

	if d := cmp.Diff(want, s.Details(), protocmp.Transform()); len(d) > 0 {
		t.Errorf("s.Details() (-want, +got): %s", d)
	}
}

func Test_rejectedPolicy(t *testing.T) {
	want := &cpb.RejectedPolicy{Rejections: 1}
	err := withRejectedPolicy(want, status.Error(codes.Internal, "this is a error"))

	got := rejectedPolicy(err)
	if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
		t.Errorf("RejectedPolicy() (-want, +got): %v", d)
	}
}

func Test_rejectedPolicy_NotStatusErr(t *testing.T) {
	err := withRejectedPolicy(&cpb.RejectedPolicy{Rejections: 1}, fmt.Errorf("this is a error"))

	got := rejectedPolicy(err)
	if got != nil {
		t.Errorf("RejectedPolicy() = %v want nil", got)
	}
}
