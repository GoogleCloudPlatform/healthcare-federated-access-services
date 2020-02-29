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
	"google.golang.org/grpc/status" /* copybara-comment */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

// withRejectedPolicy add RejectedPolicy detail to status err.
func withRejectedPolicy(rejected *cpb.RejectedPolicy, err error) error {
	s, ok := status.FromError(err)
	if !ok {
		glog.Error("not a status error")
		return err
	}

	s, err = s.WithDetails(rejected)
	if err != nil {
		glog.Errorf("status.WithDetails() failed: %v", err)
	}
	return s.Err()
}

// rejectedPolicy find RejectedPolicy attached in status error.
func rejectedPolicy(err error) *cpb.RejectedPolicy {
	s, ok := status.FromError(err)
	if !ok {
		glog.Error("not a status error")
		return nil
	}
	for _, d := range s.Details() {
		switch v := d.(type) {
		case *cpb.RejectedPolicy:
			return v
		}
	}
	return nil
}

// error types for checkAuthorization
const (
	errUntrustedIssuer          = "dam:check_auth:untrusted_issuer"
	errResourceNotFoound        = "dam:check_auth:resource_not_found"
	errResourceViewNotFoound    = "dam:check_auth:resource_view_not_found"
	errResolveAggregatesFail    = "dam:check_auth:resolve_aggregates_fail"
	errRoleNotAvailable         = "dam:check_auth:role_not_available"
	errCannotResolveServiceRole = "dam:check_auth:cannot_resolve_service_role"
	errNoPolicyDefined          = "dam:check_auth:no_policy_defined"
	errCannotEnforcePolicies    = "dam:check_auth:cannot_enforce_policies"
	errCannotValidateIdentity   = "dam:check_auth:cannot_validate_identity"
	errRejectedPolicy           = "dam:check_auth:rejected_policy"
	errRoleNotEnabled           = "dam:check_auth:role_not_enabled"
)
