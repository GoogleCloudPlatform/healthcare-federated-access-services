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
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/api/cloudresourcemanager/v1" /* copybara-comment: cloudresourcemanager */
	"google.golang.org/api/googleapi" /* copybara-comment: googleapi */
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

func Test_applyCRMChange_Errors(t *testing.T) {
	err503 := &googleapi.Error{
		Code:    503,
		Message: "503",
	}
	err400 := &googleapi.Error{
		Code:    400,
		Message: "400",
	}

	tests := []struct {
		name      string
		crm       CRMPolicy
		state     *backoffState
		wantError bool
		errorType string
		wantState *backoffState
	}{
		{
			name:      "no error",
			crm:       &fakeCRM{getResponse: &cloudresourcemanager.Policy{}},
			state:     &backoffState{},
			wantError: false,
			wantState: &backoffState{},
		},
		{
			name:      "get 503 error",
			crm:       &fakeCRM{getResponseErr: err503},
			state:     &backoffState{},
			wantError: true,
			errorType: "*errors.errorString",
			wantState: &backoffState{},
		},
		{
			name:      "get 400 error",
			crm:       &fakeCRM{getResponseErr: err400},
			state:     &backoffState{},
			wantError: true,
			errorType: "*backoff.PermanentError",
			wantState: &backoffState{},
		},
		{
			name:      "no new error, different etag",
			crm:       &fakeCRM{getResponse: &cloudresourcemanager.Policy{Etag: "2"}},
			state:     &backoffState{failedEtag: "1", prevErr: err400},
			wantError: false,
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
		{
			name:      "no new error, same etag",
			crm:       &fakeCRM{getResponse: &cloudresourcemanager.Policy{Etag: "1"}},
			state:     &backoffState{failedEtag: "1", prevErr: err400},
			wantError: true,
			errorType: "*backoff.PermanentError",
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
		{
			name: "set 503 error",
			crm: &fakeCRM{
				getResponse:    &cloudresourcemanager.Policy{Etag: "1"},
				setResponseErr: err503,
			},
			state:     &backoffState{},
			wantError: true,
			errorType: "*googleapi.Error",
			wantState: &backoffState{failedEtag: "1", prevErr: err503},
		},
		{
			name: "set 400 error",
			crm: &fakeCRM{
				getResponse:    &cloudresourcemanager.Policy{Etag: "1"},
				setResponseErr: err400,
			},
			state:     &backoffState{},
			wantError: true,
			errorType: "*googleapi.Error",
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			state := &backoffState{
				failedEtag: tc.state.failedEtag,
				prevErr:    tc.state.prevErr,
			}

			got := applyCRMChange(context.Background(), tc.crm, "email", "project", nil, time.Hour, state)
			if tc.wantError != (got != nil) {
				t.Errorf("applyCRMChange() wants error(%v)", tc.wantError)
			}

			if got != nil {
				errorType := reflect.TypeOf(got).String()
				if errorType != tc.errorType {
					t.Errorf("applyCRMChange() error type=%s, wants %s", errorType, tc.errorType)
				}
			}

			if tc.wantState.failedEtag != state.failedEtag || tc.wantState.prevErr != state.prevErr {
				t.Errorf("state want: %v, got: %v", tc.wantState, state)
			}
		})
	}
}
