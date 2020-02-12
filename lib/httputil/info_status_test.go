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

package httputil

import (
	"testing"

	"google.golang.org/grpc/codes" /* copybara-comment */
)

const (
	testStatusMsg       = "test invalid argument"
	testStatusInfoName1 = "my/status/path1"
	testStatusInfoMsg1  = "status info msg 1"
	testStatusInfoName2 = "my/status/path2"
	testStatusInfoMsg2  = "status info msg 2"
)

func TestStatus(t *testing.T) {
	stat := NewStatus(codes.InvalidArgument, testStatusMsg)
	if stat.Code() != codes.InvalidArgument {
		t.Errorf("NewStatus(codes.InvalidArgument, %q).Code() : want %v, got %v", testStatusMsg, codes.InvalidArgument, stat.Code())
	}
	if stat.Message() != testStatusMsg {
		t.Errorf("NewStatus(codes.InvalidArgument, %q).Message() : want %v, got %v", testStatusMsg, testStatusMsg, stat.Message())
	}
	if len(stat.Details()) > 0 {
		t.Errorf("stat.Details() : want empty, got %v", stat.Details())
	}
	stat = AddStatusInfo(stat, testStatusInfoName1, testStatusInfoMsg1)
	if stat.Message() != testStatusMsg {
		t.Errorf("original stat.Message() changed : want %v, got %v", testStatusMsg, stat.Message())
	}
	if len(stat.Details()) != 1 {
		t.Errorf("stat.Details() length : want 1, got %d : %v", len(stat.Details()), stat.Details())
	}
	stat = AddStatusInfo(stat, testStatusInfoName2, testStatusInfoMsg2)
	if len(stat.Details()) != 2 {
		t.Errorf("stat.Details() length : want 2, got %d : %v", len(stat.Details()), stat.Details())
	}
}
