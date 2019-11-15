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
	"net/http"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// WARNING: do not change the mappings in this file.

// 499 is a non-standard code for "Client Closed Request" and is the code
// mapped to Canceled in C++, so we do that here too for consistency.
const canceled = 499

// Notes:
//  1. FailedPrecondtion: 416 "Requested range not satisfiable" is not used
//     because it has HTTP-specific semantics that will not always apply.
//  2. OutOfRange: 416 "Requested range not satisfiable" is not used because it
//     has HTTP-specific semantics that will not always apply.
var rpc2http = map[codes.Code]int{
	codes.OK:                 http.StatusOK,
	codes.Canceled:           canceled,
	codes.InvalidArgument:    http.StatusBadRequest,
	codes.DeadlineExceeded:   http.StatusGatewayTimeout,
	codes.NotFound:           http.StatusNotFound,
	codes.AlreadyExists:      http.StatusConflict,
	codes.PermissionDenied:   http.StatusForbidden,
	codes.ResourceExhausted:  http.StatusTooManyRequests,
	codes.FailedPrecondition: http.StatusBadRequest,
	codes.Aborted:            http.StatusConflict,
	codes.OutOfRange:         http.StatusBadRequest,
	codes.Unimplemented:      http.StatusNotImplemented,
	codes.Unavailable:        http.StatusServiceUnavailable,
	codes.Unauthenticated:    http.StatusUnauthorized,
	// DataLoss, Internal, and Unknown map to the default
}

// In the mappings above, some Codes are mapped to the same HTTP
// status. Here, the HTTP status is mapped to the most general codes.Code.
var http2rpc = map[int]codes.Code{
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

// RPCCode translates an HTTP status into a codes.Code
func RPCCode(code int) codes.Code {
	if code, ok := http2rpc[code]; ok {
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

// HTTPStatus translates a codes.Code into an HTTP status.
func HTTPStatus(code codes.Code) int {
	if code, ok := rpc2http[code]; ok {
		return code
	}
	return http.StatusInternalServerError
}

// FromError translates a canonical error into an HTTP status.
func FromError(err error) int {
	return HTTPStatus(status.Code(err))
}
