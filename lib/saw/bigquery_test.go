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

	"google.golang.org/api/bigquery/v2" /* copybara-comment: bigquery */
	"google.golang.org/api/googleapi" /* copybara-comment: googleapi */
)

func Test_applyBQChange_Errors(t *testing.T) {
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
		bq        BQPolicy
		state     *backoffState
		wantError bool
		errorType string
		wantState *backoffState
	}{
		{
			name:      "no error",
			bq:        &fakeBQ{getResponse: &bigquery.Dataset{}},
			state:     &backoffState{},
			wantError: false,
			wantState: &backoffState{},
		},
		{
			name:      "get 503 error",
			bq:        &fakeBQ{getResponseErr: err503},
			state:     &backoffState{},
			wantError: true,
			errorType: "*errors.errorString",
			wantState: &backoffState{},
		},
		{
			name:      "get 400 error",
			bq:        &fakeBQ{getResponseErr: err400},
			state:     &backoffState{},
			wantError: true,
			errorType: "*backoff.PermanentError",
			wantState: &backoffState{},
		},
		{
			name:      "no new error, different etag",
			bq:        &fakeBQ{getResponse: &bigquery.Dataset{Etag: "2"}},
			state:     &backoffState{failedEtag: "1", prevErr: err400},
			wantError: false,
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
		{
			name:      "no new error, same etag",
			bq:        &fakeBQ{getResponse: &bigquery.Dataset{Etag: "1"}},
			state:     &backoffState{failedEtag: "1", prevErr: err400},
			wantError: true,
			errorType: "*backoff.PermanentError",
			wantState: &backoffState{failedEtag: "1", prevErr: err400},
		},
		{
			name: "set 503 error",
			bq: &fakeBQ{
				getResponse:    &bigquery.Dataset{Etag: "1"},
				setResponseErr: err503,
			},
			state:     &backoffState{},
			wantError: true,
			errorType: "*googleapi.Error",
			wantState: &backoffState{failedEtag: "1", prevErr: err503},
		},
		{
			name: "set 400 error",
			bq: &fakeBQ{
				getResponse:    &bigquery.Dataset{Etag: "1"},
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
			got := applyBQDSChange(context.Background(), tc.bq, "email", "project", "ds", nil, state)
			if tc.wantError != (got != nil) {
				t.Errorf("applyBQDSChange() wants error(%v)", tc.wantError)
			}

			if got != nil {
				errorType := reflect.TypeOf(got).String()
				if errorType != tc.errorType {
					t.Errorf("applyBQDSChange() error type=%s, wants %s", errorType, tc.errorType)
				}
			}

			if tc.wantState.failedEtag != state.failedEtag || tc.wantState.prevErr != state.prevErr {
				t.Errorf("state want: %v, got: %v", tc.wantState, state)
			}
		})
	}
}
