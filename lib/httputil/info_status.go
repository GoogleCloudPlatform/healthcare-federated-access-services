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
	"strings"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */

	errpb "google.golang.org/genproto/googleapis/rpc/errdetails" /* copybara-comment */
)

var (
	// NewStatus is temprorary aliases.
	NewStatus = status.New
)

// NewInfoStatus returns a standard RPC-style error message with ErrorInfo details.
func NewInfoStatus(code codes.Code, name, msg string) *status.Status {
	return AddStatusInfo(NewStatus(code, msg), name, msg)
}

// AddStatusInfo returns a new status that includes an additional ErrorInfo entry.
func AddStatusInfo(s *status.Status, name, msg string) *status.Status {
	detail := &errpb.ResourceInfo{
		ResourceName: name,
		Description:  msg,
	}
	return AddStatusDetails(s, detail)
}

// AddStatusDetails adds a details message to a status.
func AddStatusDetails(s *status.Status, details ...proto.Message) *status.Status {
	es, err := s.WithDetails(details...)
	if err == nil {
		return es
	}
	return s
}

// StatusPath combines multiple path elements into one string path.
func StatusPath(list ...string) string {
	return strings.Join(list, "/")
}
