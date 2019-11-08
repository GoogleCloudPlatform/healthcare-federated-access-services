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

package common

import (
	"net/http"
	"strings"

	"github.com/golang/protobuf/proto"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	errpb "google.golang.org/genproto/googleapis/rpc/errdetails"
)

// 499 is a non-standard code for "Client Closed Request" and is the code
// mapped to Canceled in C++, so we do that here too for consistency.
const canceled = 499

var canonical2http = map[codes.Code]int{
	codes.OK:                 http.StatusOK,
	codes.Canceled:           canceled,
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.DeadlineExceeded:   http.StatusGatewayTimeout,
	codes.NotFound:           http.StatusNotFound,
	codes.AlreadyExists:      http.StatusConflict,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.ResourceExhausted:  http.StatusTooManyRequests,
	codes.FailedPrecondition: http.StatusFailedDependency,
	codes.Aborted:            http.StatusConflict,
	codes.OutOfRange:         http.StatusBadRequest,
	codes.Unimplemented:      http.StatusNotImplemented,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.Unauthenticated:    http.StatusUnauthorized,
	// DataLoss, Internal, and Unknown map to the default
}

// In the mappings above, some Codes are mapped to the same HTTP
// status. Here, the HTTP status is mapped to the most general codes.Code.
var http2canonical = map[int]codes.Code{
	http.StatusOK:                           codes.OK,
	http.StatusBadRequest:                   codes.InvalidArgument,
	http.StatusForbidden:                    codes.PermissionDenied,
	http.StatusNotFound:                     codes.NotFound,
	http.StatusConflict:                     codes.Aborted,
	http.StatusRequestedRangeNotSatisfiable: codes.OutOfRange,
	http.StatusTooManyRequests:              codes.ResourceExhausted,
	canceled:                                codes.Canceled,
	http.StatusGatewayTimeout:               codes.DeadlineExceeded,
	http.StatusNotImplemented:               codes.Unimplemented,
	http.StatusServiceUnavailable:           codes.Unavailable,
	http.StatusUnauthorized:                 codes.Unauthenticated,
}

// ToCode translates an HTTP status into a codes.Code
func ToCode(code int) codes.Code {
	if code, ok := http2canonical[code]; ok {
		return code
	}

	switch {
	case code >= 200 && code < 300:
		return codes.OK
	case code >= 400 && code < 500:
		return codes.FailedPrecondition
	case code >= 500 && code < 600:
		return codes.Internal
	}
	return codes.Unknown
}

// FromCode translates a codes.Code into an HTTP status.
func FromCode(code codes.Code) int {
	if code, ok := canonical2http[code]; ok {
		return code
	}
	return http.StatusInternalServerError
}

// FromError translates a canonical error into an HTTP status.
func FromError(err error) int {
	return FromCode(status.Code(err))
}

// NewStatus returns a standard RPC-style error message.
func NewStatus(code codes.Code, msg string) *status.Status {
	return status.New(code, msg)
}

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
