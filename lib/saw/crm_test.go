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
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */
)

func Test_crmPolicyAdd_DisableIAMConditionExpiry(t *testing.T) {
	globalflags.DisableIAMConditionExpiry = true
	timeNow = fakeTime
	t.Cleanup(func() {
		globalflags.DisableIAMConditionExpiry = false
		timeNow = time.Now
	})

	ttl := time.Hour
	tests := []struct {
		name   string
		policy *cloudresourcemanager.Policy
		role   string
		member string
		want   *cloudresourcemanager.Policy
	}{
		{
			name: "insert new binding",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
					},
				},
			},
		},
		{
			name: "insert new member",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:456@example.com"},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role: "role",
						Members: []string{
							"serviceAccount:456@example.com",
							"serviceAccount:123@example.com",
						},
					},
				},
			},
		},
		{
			name: "not modify",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crmPolicyAdd(tc.policy, tc.role, tc.member, ttl)
			if d := cmp.Diff(tc.want, tc.policy, protocmp.Transform()); len(d) > 0 {
				t.Errorf("crmPolicyAdd() (-want, +got): %s", d)
			}
		})
	}
}

func Test_crmPolicyAdd_EnableIAMConditionExpiry(t *testing.T) {
	longerExp := timeNow().Add(time.Hour * 24)
	ttl := time.Hour
	newExp := timeNow().Add(ttl)

	tests := []struct {
		name   string
		policy *cloudresourcemanager.Policy
		role   string
		member string
		want   *cloudresourcemanager.Policy
	}{
		{
			name: "insert new binding",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &cloudresourcemanager.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(newExp),
						},
					},
				},
			},
		},
		{
			name: "insert new binding same rule for other user",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:456@example.com"},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role: "role",
						Members: []string{
							"serviceAccount:456@example.com",
						},
					},
					{
						Role: "role",
						Members: []string{
							"serviceAccount:123@example.com",
						},
						Condition: &cloudresourcemanager.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(newExp),
						},
					},
				},
			},
		},
		{
			name: "update condition",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &cloudresourcemanager.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(timeNow()),
						},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &cloudresourcemanager.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(newExp),
						},
					},
				},
			},
		},
		{
			name: "not update condition",
			policy: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &cloudresourcemanager.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(longerExp),
						},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &cloudresourcemanager.Policy{
				Bindings: []*cloudresourcemanager.Binding{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &cloudresourcemanager.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(longerExp),
						},
					},
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			crmPolicyAdd(tc.policy, tc.role, tc.member, ttl)
			if d := cmp.Diff(tc.want, tc.policy, protocmp.Transform()); len(d) > 0 {
				t.Errorf("crmPolicyAdd() (-want, +got): %s", d)
			}
		})
	}
}

func fakeTime() time.Time {
	return time.Time{}
}
