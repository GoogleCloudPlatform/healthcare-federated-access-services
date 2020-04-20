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
		glog.Errorf("set iam for crm failed: etag=%s err=%v", policy.Etag, err)
		return err
	}
	return nil
}

// crmPolicyAdd adds a member to a role in a CRM policy.
func crmPolicyAdd(policy *cloudresourcemanager.Policy, role, member string, ttl time.Duration) {
	bindings := fromCRMBindings(policy.Bindings)
	bindings = addPolicyBinding(bindings, role, member, ttl)
	policy.Bindings = toCRMBindings(bindings)
}

func fromCRMBindings(in []*cloudresourcemanager.Binding) []*iamBinding {
	var res []*iamBinding
	for _, b := range in {
		res = append(res, fromCRMBinding(b))
	}
	return res
}

func fromCRMBinding(in *cloudresourcemanager.Binding) *iamBinding {
	if in == nil {
		return nil
	}
	return &iamBinding{
		role:      in.Role,
		members:   in.Members,
		condition: fromCRMCondition(in.Condition),
	}
}

func fromCRMCondition(in *cloudresourcemanager.Expr) *iamCondition {
	if in == nil {
		return nil
	}
	return &iamCondition{
		title:       in.Title,
		description: in.Description,
		location:    in.Location,
		expression:  in.Expression,
	}
}

func toCRMBindings(in []*iamBinding) []*cloudresourcemanager.Binding {
	var res []*cloudresourcemanager.Binding
	for _, b := range in {
		res = append(res, toCRMBinding(b))
	}
	return res
}

func toCRMBinding(in *iamBinding) *cloudresourcemanager.Binding {
	if in == nil {
		return nil
	}
	return &cloudresourcemanager.Binding{
		Role:      in.role,
		Members:   in.members,
		Condition: toCRMCondition(in.condition),
	}
}

func toCRMCondition(in *iamCondition) *cloudresourcemanager.Expr {
	if in == nil {
		return nil
	}
	return &cloudresourcemanager.Expr{
		Title:       in.title,
		Description: in.description,
		Location:    in.location,
		Expression:  in.expression,
	}
}
