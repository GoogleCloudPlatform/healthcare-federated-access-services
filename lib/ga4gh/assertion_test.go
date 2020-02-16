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

package ga4gh

import (
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func Test_toAssertionProto(t *testing.T) {
	ts := time.Now().Unix()

	in := Assertion{
		Type:     AffiliationAndRole,
		Value:    "public.citizen-scientist@no.organization",
		Source:   "https://no.organization",
		By:       Self,
		Asserted: ts,
		Conditions: Conditions{[]Condition{{
			Type:  AffiliationAndRole,
			Value: "pattern:*@no.organization",
		}}},
	}
	got := toAssertionProto(in)
	want := &cpb.Assertion{
		AnyOfConditions: []*cpb.ConditionSet{{AllOf: []*cpb.Condition{{
			Type:  "AffiliationAndRole",
			Value: "pattern:*@no.organization",
		}}}},
		Type:     "AffiliationAndRole",
		Value:    "public.citizen-scientist@no.organization",
		Asserted: ts,
		By:       "self",
		Source:   "https://no.organization",
	}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("toAssertionProto() returned diff (-want +got):\n%s", diff)
	}
}
