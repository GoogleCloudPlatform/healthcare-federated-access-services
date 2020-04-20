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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */

	glog "github.com/golang/glog" /* copybara-comment */
	gcs "google.golang.org/api/storage/v1" /* copybara-comment: storage */
)

// GCSPolicyClient is used to manage IAM policy on GCS buckets.
type GCSPolicyClient struct {
	gcsc *gcs.Service
}

func (c *GCSPolicyClient) Get(ctx context.Context, bkt string, billingProject string) (*gcs.Policy, error) {
	get := c.gcsc.Buckets.GetIamPolicy(bkt)
	get.OptionsRequestedPolicyVersion(iamVersion)
	if billingProject != "" {
		get = get.UserProject(billingProject)
	}
	policy, err := get.Context(ctx).Do()
	if err != nil {
		return nil, err
	}
	// force policy upgrade.
	if policy.Version < iamVersion {
		policy.Version = iamVersion
	}
	return policy, nil
}

func (c *GCSPolicyClient) Set(ctx context.Context, bkt string, billingProject string, policy *gcs.Policy) error {
	set := c.gcsc.Buckets.SetIamPolicy(bkt, policy)
	if billingProject != "" {
		set = set.UserProject(billingProject)
	}
	if _, err := set.Context(ctx).Do(); err != nil {
		return err
	}
	return nil
}

func applyGCSChange(ctx context.Context, gcsc GCSPolicy, email string, bkt string, roles []string, billingProject string, ttl time.Duration, state *backoffState) error {
	policy, err := gcsc.Get(ctx, bkt, billingProject)
	if err != nil {
		return convertToPermanentErrorIfApplicable(err, fmt.Errorf("getting IAM policy for bucket %q: %v", bkt, err))
	}
	if len(state.failedEtag) > 0 && state.failedEtag == policy.Etag {
		return convertToPermanentErrorIfApplicable(state.prevErr, fmt.Errorf("setting IAM policy for bucket %q on service account %q: %v", bkt, email, state.prevErr))
	}

	for _, role := range roles {
		gcsPolicyAdd(policy, role, "serviceAccount:"+email, ttl)
	}

	if err := gcsc.Set(ctx, bkt, billingProject, policy); err != nil {
		state.failedEtag = policy.Etag
		state.prevErr = err
		glog.Errorf("set iam for gcs failed: etag=%s err=%v", policy.Etag, err)
		return err
	}
	return nil
}

// gcsPolicyAdd adds a member to role in a GCS policy.
func gcsPolicyAdd(policy *gcs.Policy, role, member string, ttl time.Duration) {
	if globalflags.DisableIAMConditionExpiry {
		gcsPolicyAddWithConditionExpDisabled(policy, role, member)
		return
	}
	gcsPolicyAddWithConditionExpEnabled(policy, role, member, ttl)
}

// gcsPolicyAddWithConditionExpDisabled adds a member to role in a GCS policy.
func gcsPolicyAddWithConditionExpDisabled(policy *gcs.Policy, role, member string) {
	var binding *gcs.PolicyBindings
	for _, b := range policy.Bindings {
		if b.Role == role {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &gcs.PolicyBindings{Role: role}
		policy.Bindings = append(policy.Bindings, binding)
	}

	for _, m := range binding.Members {
		if m == member {
			return
		}
	}
	binding.Members = append(binding.Members, member)
}

// gcsPolicyAddWithConditionExpEnabled adds a member to role in a GCS policy with iam condition managed expiry.
func gcsPolicyAddWithConditionExpEnabled(policy *gcs.Policy, role, member string, ttl time.Duration) {
	var binding *gcs.PolicyBindings
	for _, b := range policy.Bindings {
		if b.Role == role && strutil.SliceOnlyContains(b.Members, member) {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &gcs.PolicyBindings{
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

	binding.Condition = &gcs.Expr{
		Title:      "Expiry",
		Expression: toExpiryConditionExpr(newExp),
	}
}
