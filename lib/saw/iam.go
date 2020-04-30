// Copyright 2020 Google LLC.
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
	"fmt"
	"regexp"
	"time"

	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */
)

const (
	// iamVersion use 3 to support iam condition.
	iamVersion = 3
)

var (
	expiryConditionRE   = regexp.MustCompile(`^request\.time < timestamp\("(.*?)"\)$`)
	conditionExprFormat = `request.time < timestamp("%s")`
	timeNow             = time.Now
)

// expiryInCondition finds expiry in condition expression
func expiryInCondition(condition string) time.Time {
	if len(condition) == 0 {
		return time.Time{}
	}
	match := expiryConditionRE.FindStringSubmatch(condition)
	if len(match) > 1 {
		if ts, err := time.Parse(time.RFC3339, match[1]); err == nil {
			return ts
		}
	}

	return time.Time{}
}

// toExpiryConditionExpr builds the condition expr with given timestamp
func toExpiryConditionExpr(exp time.Time) string {
	timeStr := exp.Format(time.RFC3339)
	return fmt.Sprintf(conditionExprFormat, timeStr)
}

// iamBinding nomalize binding struct in gcs and cloudresourcemanager
type iamBinding struct {
	role      string
	members   []string
	condition *iamCondition
}

// iamBinding nomalize condition expr struct in gcs and cloudresourcemanager
type iamCondition struct {
	description string
	expression  string
	location    string
	title       string
}

// addPolicyBinding adds a member to role in bindings.
func addPolicyBinding(bindings []*iamBinding, role, member string, ttl time.Duration) []*iamBinding {
	if globalflags.DisableIAMConditionExpiry {
		return addPolicyBindingWithConditionExpDisabled(bindings, role, member)
	}
	return addPolicyBindingWithConditionExpEnabled(bindings, role, member, ttl)
}

// addPolicyBindingWithConditionExpEnabled adds a member to role in bindings with iam condition managed expiry.
func addPolicyBindingWithConditionExpEnabled(bindings []*iamBinding, role, member string, ttl time.Duration) []*iamBinding {
	var binding *iamBinding
	for _, b := range bindings {
		if b.role == role && strutil.SliceOnlyContains(b.members, member) {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &iamBinding{
			role:    role,
			members: []string{member},
		}
		bindings = append(bindings, binding)
	}

	// add the expiry condition to binding.
	newExp := timeNow().Add(ttl)
	exp := time.Time{}

	if binding.condition != nil {
		exp = expiryInCondition(binding.condition.expression)
	}

	// if condition already has expiry after the new request, do not modify.
	if exp.Before(newExp) {
		binding.condition = &iamCondition{
			title:      "Expiry",
			expression: toExpiryConditionExpr(newExp),
		}
	}

	return bindings
}

// addPolicyBindingWithConditionExpDisabled adds a member to role in bindings.
func addPolicyBindingWithConditionExpDisabled(bindings []*iamBinding, role, member string) []*iamBinding {
	var binding *iamBinding
	for _, b := range bindings {
		if b.role == role {
			binding = b
			break
		}
	}
	if binding == nil {
		binding = &iamBinding{
			role:    role,
			members: []string{member},
		}
		return append(bindings, binding)
	}

	if !stringset.Contains(binding.members, member) {
		binding.members = append(binding.members, member)
	}

	return bindings
}
