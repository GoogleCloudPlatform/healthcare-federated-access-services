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
	"google.golang.org/api/googleapi" /* copybara-comment: googleapi */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/globalflags" /* copybara-comment: globalflags */

	gcs "google.golang.org/api/storage/v1" /* copybara-comment: storage */
)

func Test_gcsPolicyAdd_DisableIAMConditionExpiry(t *testing.T) {
	globalflags.DisableIAMConditionExpiry = true
	timeNow = fakeTime
	t.Cleanup(func() {
		globalflags.DisableIAMConditionExpiry = false
		timeNow = time.Now
	})

	ttl := time.Hour
	tests := []struct {
		name   string
		policy *gcs.Policy
		role   string
		member string
		want   *gcs.Policy
	}{
		{
			name: "insert new binding",
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
					},
				},
			},
		},
		{
			name: "insert new member",
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:456@example.com"},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
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
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
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
			gcsPolicyAdd(tc.policy, tc.role, tc.member, ttl)
			if d := cmp.Diff(tc.want, tc.policy, protocmp.Transform()); len(d) > 0 {
				t.Errorf("gcsPolicyAdd() (-want, +got): %s", d)
			}
		})
	}
}

func Test_gcsPolicyAdd_EnableIAMConditionExpiry(t *testing.T) {
	longerExp := timeNow().Add(time.Hour * 24)
	ttl := time.Hour
	newExp := timeNow().Add(ttl)

	tests := []struct {
		name   string
		policy *gcs.Policy
		role   string
		member string
		want   *gcs.Policy
	}{
		{
			name: "insert new binding",
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &gcs.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(newExp),
						},
					},
				},
			},
		},
		{
			name: "insert new binding same rule for other user",
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:456@example.com"},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
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
						Condition: &gcs.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(newExp),
						},
					},
				},
			},
		},
		{
			name: "update condition",
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &gcs.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(timeNow()),
						},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &gcs.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(newExp),
						},
					},
				},
			},
		},
		{
			name: "not update condition",
			policy: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &gcs.Expr{
							Title:      "Expiry",
							Expression: toExpiryConditionExpr(longerExp),
						},
					},
				},
			},
			role:   "role",
			member: "serviceAccount:123@example.com",
			want: &gcs.Policy{
				Bindings: []*gcs.PolicyBindings{
					{
						Role:    "role",
						Members: []string{"serviceAccount:123@example.com"},
						Condition: &gcs.Expr{
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
			gcsPolicyAdd(tc.policy, tc.role, tc.member, ttl)
			if d := cmp.Diff(tc.want, tc.policy, protocmp.Transform()); len(d) > 0 {
				t.Errorf("gcsPolicyAdd() (-want, +got): %s", d)
			}
		})
	}
}

func Test_applyGCSChange_Errors(t *testing.T) {
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
		gcs       GCSPolicy
		state     *backoffState
		wantError bool
		errorType string
		wantState *backoffState
	}{
		{
			name:      "no error",
			gcs:       &fakeGCS{getResponse: &gcs.Policy{}},
			state:     &backoffState{},
			wantError: false,
			wantState: &backoffState{},
		},
		{
			name:      "get 503 error",
			gcs:       &fakeGCS{getResponseErr: err503},
			state:     &backoffState{},
			wantError: true,
			errorType: "*errors.errorString",
			wantState: &backoffState{},
		},
		{
			name:      "get 400 error",
			gcs:       &fakeGCS{getResponseErr: err400},
			state:     &backoffState{},
			wantError: true,
			errorType: "*backoff.PermanentError",
			wantState: &backoffState{},
		},
		{
			name:      "no new error, different etag",
			gcs:       &fakeGCS{getResponse: &gcs.Policy{Etag: "2"}},
			state:     &backoffState{failedEtag: "1", prevErr: err400},
			wantError: false,
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
		{
			name:      "no new error, same etag",
			gcs:       &fakeGCS{getResponse: &gcs.Policy{Etag: "1"}},
			state:     &backoffState{failedEtag: "1", prevErr: err400},
			wantError: true,
			errorType: "*backoff.PermanentError",
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
		{
			name: "set 503 error",
			gcs: &fakeGCS{
				getResponse:    &gcs.Policy{Etag: "1"},
				setResponseErr: err503,
			},
			state:     &backoffState{},
			wantError: true,
			errorType: "*googleapi.Error",
			wantState: &backoffState{failedEtag: "1", prevErr: err503},
		},
		{
			name: "set 400 error",
			gcs: &fakeGCS{
				getResponse:    &gcs.Policy{Etag: "1"},
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

			got := applyGCSChange(context.Background(), tc.gcs, "email", "project", nil, "proj", time.Hour, state)
			if tc.wantError != (got != nil) {
				t.Errorf("applyGCSChange() wants error(%v)", tc.wantError)
			}

			if got != nil {
				errorType := reflect.TypeOf(got).String()
				if errorType != tc.errorType {
					t.Errorf("applyGCSChange() error type=%s, wants %s", errorType, tc.errorType)
				}
			}

			if tc.wantState.failedEtag != state.failedEtag || tc.wantState.prevErr != state.prevErr {
				t.Errorf("state want: %v, got: %v", tc.wantState, state)
			}
		})
	}
}
