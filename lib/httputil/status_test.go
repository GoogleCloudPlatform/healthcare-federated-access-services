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
	"testing"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
)

func TestHTTPStatus(t *testing.T) {
	tests := []struct {
		in   codes.Code
		want int
	}{
		// Test the explicit mappings
		{codes.OK, http.StatusOK},
		{codes.Canceled, canceled},
		{codes.InvalidArgument, http.StatusBadRequest},
		{codes.DeadlineExceeded, http.StatusGatewayTimeout},
		{codes.NotFound, http.StatusNotFound},
		{codes.AlreadyExists, http.StatusConflict},
		{codes.PermissionDenied, http.StatusForbidden},
		{codes.ResourceExhausted, http.StatusTooManyRequests},
		{codes.FailedPrecondition, http.StatusBadRequest},
		{codes.Aborted, http.StatusConflict},
		{codes.OutOfRange, http.StatusBadRequest},
		{codes.Unimplemented, http.StatusNotImplemented},
		{codes.Unavailable, http.StatusServiceUnavailable},
		{codes.Unauthenticated, http.StatusUnauthorized},
		// Test the default mapping
		{codes.DataLoss, http.StatusInternalServerError},
		{codes.Internal, http.StatusInternalServerError},
		{codes.Unknown, http.StatusInternalServerError},
	}

	for _, tc := range tests {
		if got := HTTPStatus(tc.in); got != tc.want {
			t.Errorf("HTTPStatus(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestRPCCode(t *testing.T) {
	tests := []struct {
		in   int
		want codes.Code
	}{
		// Test the explicit mappings
		{http.StatusOK, codes.OK},
		{http.StatusBadRequest, codes.InvalidArgument},
		{http.StatusForbidden, codes.PermissionDenied},
		{http.StatusNotFound, codes.NotFound},
		{http.StatusConflict, codes.Aborted},
		{http.StatusRequestedRangeNotSatisfiable, codes.OutOfRange},
		{http.StatusTooManyRequests, codes.ResourceExhausted},
		{canceled, codes.Canceled},
		{http.StatusGatewayTimeout, codes.DeadlineExceeded},
		{http.StatusNotImplemented, codes.Unimplemented},
		{http.StatusServiceUnavailable, codes.Unavailable},
		{http.StatusUnauthorized, codes.Unauthenticated},
		// Test the ranged mappings
		{http.StatusIMUsed, codes.OK},
		{http.StatusPaymentRequired, codes.FailedPrecondition},
		{http.StatusLoopDetected, codes.Internal},
		{http.StatusSeeOther, codes.Unknown},
	}

	for _, tc := range tests {
		if got := RPCCode(tc.in); got != tc.want {
			t.Errorf("RPCCode(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func Test_FromError(t *testing.T) {
	got := FromError(status.Errorf(codes.NotFound, "resource not found"))
	want := http.StatusNotFound
	if got != want {
		t.Fatalf("FromError(NotFound Error) = %v, want %v", got, want)
	}
}

func Test_IsHTTPSuccess(t *testing.T) {
	tests := []struct {
		in   int
		want bool
	}{
		{
			in:   http.StatusOK,
			want: true,
		},
		{
			in:   http.StatusMovedPermanently,
			want: false,
		},
		{
			in:   http.StatusBadRequest,
			want: false,
		},
		{
			in:   http.StatusInternalServerError,
			want: false,
		},
	}
	for _, tc := range tests {
		if got := IsHTTPSuccess(tc.in); got != tc.want {
			t.Errorf("IsHTTPSuccess(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func Test_IsHTTPRedirect(t *testing.T) {
	tests := []struct {
		in   int
		want bool
	}{
		{
			in:   http.StatusOK,
			want: false,
		},
		{
			in:   http.StatusMovedPermanently,
			want: true,
		},
		{
			in:   http.StatusBadRequest,
			want: false,
		},
		{
			in:   http.StatusInternalServerError,
			want: false,
		},
	}
	for _, tc := range tests {
		if got := IsHTTPRedirect(tc.in); got != tc.want {
			t.Errorf("IsHTTPRedirect(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func Test_IsHTTPClientError(t *testing.T) {
	tests := []struct {
		in   int
		want bool
	}{
		{
			in:   http.StatusOK,
			want: false,
		},
		{
			in:   http.StatusMovedPermanently,
			want: false,
		},
		{
			in:   http.StatusBadRequest,
			want: true,
		},
		{
			in:   http.StatusInternalServerError,
			want: false,
		},
	}
	for _, tc := range tests {
		if got := IsHTTPClientError(tc.in); got != tc.want {
			t.Errorf("IsHTTPClientError(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func Test_IsHTTPServerError(t *testing.T) {
	tests := []struct {
		in   int
		want bool
	}{
		{
			in:   http.StatusOK,
			want: false,
		},
		{
			in:   http.StatusMovedPermanently,
			want: false,
		},
		{
			in:   http.StatusBadRequest,
			want: false,
		},
		{
			in:   http.StatusInternalServerError,
			want: true,
		},
	}
	for _, tc := range tests {
		if got := IsHTTPServerError(tc.in); got != tc.want {
			t.Errorf("IsHTTPServerError(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func Test_IsHTTPError(t *testing.T) {
	tests := []struct {
		in   int
		want bool
	}{
		{
			in:   http.StatusOK,
			want: false,
		},
		{
			in:   http.StatusMovedPermanently,
			want: false,
		},
		{
			in:   http.StatusBadRequest,
			want: true,
		},
		{
			in:   http.StatusInternalServerError,
			want: true,
		},
	}
	for _, tc := range tests {
		if got := IsHTTPError(tc.in); got != tc.want {
			t.Errorf("IsHTTPError(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
