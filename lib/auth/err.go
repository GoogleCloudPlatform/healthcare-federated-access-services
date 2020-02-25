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

package auth

import (
	"google.golang.org/grpc/status" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
	edpb "google.golang.org/genproto/googleapis/rpc/errdetails" /* copybara-comment */
)

func withErrorType(typ string, err error) error {
	s, ok := status.FromError(err)
	if !ok {
		glog.Error("not a status error")
		return err
	}

	s, err = s.WithDetails(&edpb.ErrorInfo{Type: typ})
	if err != nil {
		glog.Errorf("status.WithDetails() failed: %v", err)
	}
	return s.Err()
}

func errorType(err error) string {
	s, ok := status.FromError(err)
	if !ok {
		glog.Error("not a status error")
		return string(errUnkown)
	}
	for _, d := range s.Details() {
		switch v := d.(type) {
		case *edpb.ErrorInfo:
			return v.GetType()
		}
	}
	return string(errUnkown)
}

type errType = string

const (
	errBodyTooLarge        errType = "req:body_too_large"
	errClientUnavailable   errType = "client:unavailable"
	errClientMissing       errType = "client:missing"
	errClientInvalid       errType = "client:invalid"
	errSecretMismatch      errType = "client:secret_mismatch"
	errTokenInvalid        errType = "token:invalid"
	errIssMismatch         errType = "id:iss_mismatch"
	errSubMissing          errType = "id:sub_missing"
	errAudMismatch         errType = "id:aud_mismatch"
	errIDInvalid           errType = "id:invalid"
	errVerifierUnavailable errType = "oidc:verifier_unavailable"
	errIDVerifyFailed      errType = "id:verify_failed"
	errNotAdmin            errType = "role:user_not_admin"
	errUserMismatch        errType = "role:user_mismatch"
	errUnknownRole         errType = "role:unknown_role"
	errUnkown              errType = ""
)
