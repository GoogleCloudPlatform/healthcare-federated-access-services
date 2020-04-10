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

package saw

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */

	glog "github.com/golang/glog" /* copybara-comment */
)

// CRMPolicyClient is used to manage IAM policy on CRM projects.
type CRMPolicyClient struct {
	crmc *cloudresourcemanager.Service
}

func (c *CRMPolicyClient) Get(ctx context.Context, project string) (*cloudresourcemanager.Policy, error) {
	req := &cloudresourcemanager.GetIamPolicyRequest{
		Options: &cloudresourcemanager.GetPolicyOptions{
			RequestedPolicyVersion: iamVersion,
		},
	}
	policy, err := c.crmc.Projects.GetIamPolicy(project, req).Context(ctx).Do()
	if err != nil {
		return nil, err
	}

	// force policy upgrade.
	if policy.Version < iamVersion {
		policy.Version = iamVersion
	}
	return policy, nil
}

func (c *CRMPolicyClient) Set(ctx context.Context, project string, policy *cloudresourcemanager.Policy) error {
	_, err := c.crmc.Projects.SetIamPolicy(project, &cloudresourcemanager.SetIamPolicyRequest{Policy: policy}).Context(ctx).Do()
	return err
}

func applyCRMChange(ctx context.Context, crmc CRMPolicy, email string, project string, roles []string, ttl time.Duration, state *backoffState) error {
	policy, err := crmc.Get(ctx, project)
	if err != nil {
		return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting IAM policy for project %q: %v", project, err))
	}
	// If the etag of the policy that previously failed to set still matches the etag of the
	// the current state of the policy, then the previous error returned by SetIamPolicy is not
	// related to etag and is hence a permanent error. Note that having matching etags doesn't
	// necessarily mean that the previous error is an etag error since the policy might have
	// changed between retry calls.
	if len(state.failedEtag) > 0 && state.failedEtag == policy.Etag {
		return convertToPermanentErrorIfApplicable(state.prevErr, fmt.Errorf("setting IAM policy for project %q on service account %q: %v", project, email, state.prevErr))
	}

	for _, role := range roles {
		crmPolicyAdd(policy, role, "serviceAccount:"+email, ttl)
	}

	if err := crmc.Set(ctx, project, policy); err != nil {
		state.failedEtag = policy.Etag
		state.prevErr = err
		glog.Errorf("set iam for crm failed: %v", err)
	}
	return err
}

// crmPolicyAdd adds a member to a role in a CRM policy.
func crmPolicyAdd(policy *cloudresourcemanager.Policy, role, member string, ttl time.Duration) {
	if globalflags.DisableIAMConditionExpiry {
		crmPolicyAddWithConditionExpDisabled(policy, role, member)
		return
	}
	crmPolicyAddWithConditionExpEnabled(policy, role, member, ttl)
}

// crmPolicyAddWithConditionExpDisabled adds a member to a role in a CRM policy.
func crmPolicyAddWithConditionExpDisabled(policy *cloudresourcemanager.Policy, role, member string) {
	// Retrieve the existing binding for the given role if available, otherwise
	// create one.
	var binding *cloudresourcemanager.Binding
	for _, b := range policy.Bindings {
		if b.Role == role {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &cloudresourcemanager.Binding{
			Role:    role,
			Members: []string{},
		}
		policy.Bindings = append(policy.Bindings, binding)
	}
	for _, m := range binding.Members {
		if m == member {
			return
		}
	}
	binding.Members = append(binding.Members, member)
}

// crmPolicyAddWithConditionExpEnabled adds a member to role in a GCS policy with iam condition managed expiry.
func crmPolicyAddWithConditionExpEnabled(policy *cloudresourcemanager.Policy, role, member string, ttl time.Duration) {
	var binding *cloudresourcemanager.Binding
	for _, b := range policy.Bindings {
		if b.Role == role && strutil.SliceOnlyContains(b.Members, member) {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &cloudresourcemanager.Binding{
			Role:    role,
			Members: []string{member},
		}
		policy.Bindings = append(policy.Bindings, binding)
	}

	// add the expiry condition to binding.
	// if condition already has expiry after thr new request, do not modify.
	newExp := timeNow().Add(ttl)
	exp := time.Time{}

	if binding.Condition != nil {
		exp = expiryInCondition(binding.Condition.Expression)
	}

	if exp.After(newExp) {
		return
	}

	binding.Condition = &cloudresourcemanager.Expr{
		Title:      "Expiry",
		Expression: toExpiryConditionExpr(newExp),
	}
}
