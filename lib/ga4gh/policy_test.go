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
	"context"
	"testing"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/localsign" /* copybara-comment: localsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestPolicyTest(t *testing.T) {
	ctx := context.Background()
	issuers := TrustedIssuers{
		Issuer(testkeys.VisaIssuer0): nil,
		Issuer(testkeys.VisaIssuer1): map[Source]bool{"": true},
	}
	sources := TrustedSources{
		"stanford": map[Type][]RegExp{
			AffiliationAndRole: nil,
			LinkedIdentities:   {".*"},
		},
	}
	allow := Conditions{{{
		Type:  AffiliationAndRole,
		Value: "pattern:*",
	}}}
	policy, err := NewPolicy(issuers, sources, allow, nil, nil)
	if err != nil {
		t.Fatalf("NewPolicy(%v,%v,%v,%v,%v) failed: %v", issuers, sources, allow, nil, nil, err)
	}

	issuer := testkeys.Keys[testkeys.VisaIssuer0]
	ids := []ID{
		{Issuer: issuer.ID, Subject: "alice0"},
		{Issuer: issuer.ID, Subject: "alice1"},
	}
	visa0 := newVisa(t, issuer, ids[0], Assertion{Type: LinkedIdentities, Value: LinkedIDValue(ids[1:]), Source: "stanford"}, "openid", "")
	visa1 := newVisa(t, issuer, ids[0], Assertion{Type: AffiliationAndRole, Value: "alice@stanford.edu", Source: "stanford"}, "openid", "")

	broker := testkeys.Keys[testkeys.PassportBroker0]
	d := &AccessData{}

	signer := localsign.New(&broker)
	access, err := NewAccessFromData(ctx, d, signer)
	if err != nil {
		t.Fatalf("NewPassportFromData() failed: %v", err)
	}
	passport := &Passport{
		Access: access,
		Visas:  []*Visa{visa0, visa1},
	}

	if err := policy.Test(ctx, passport); err != nil {
		t.Fatalf("policy.Test(passport) failed: %v", err)
	}
}

func TestPolicyTest_NotAllowed(t *testing.T) {
	ctx := context.Background()
	issuers := TrustedIssuers{
		Issuer(testkeys.VisaIssuer0): nil,
		Issuer(testkeys.VisaIssuer1): map[Source]bool{"": true},
	}
	sources := TrustedSources{
		"stanford": map[Type][]RegExp{
			AffiliationAndRole: nil,
			LinkedIdentities:   {".*"},
		},
	}
	allow := Conditions{{{
		Type:  AffiliationAndRole,
		Value: "pattern:*",
	}}}
	policy, err := NewPolicy(issuers, sources, allow, nil, nil)
	if err != nil {
		t.Fatalf("NewPolicy(%v,%v,%v,%v,%v) failed: %v", issuers, sources, allow, nil, nil, err)
	}

	issuer := testkeys.Keys[testkeys.VisaIssuer0]
	ids := []ID{
		{Issuer: issuer.ID, Subject: "alice0"},
		{Issuer: issuer.ID, Subject: "alice1"},
	}
	visa0 := newVisa(t, issuer, ids[0], Assertion{Type: LinkedIdentities, Value: LinkedIDValue(ids[1:]), Source: "stanford"}, "openid", "")

	broker := testkeys.Keys[testkeys.PassportBroker0]
	d := &AccessData{}

	signer := localsign.New(&broker)
	access, err := NewAccessFromData(ctx, d, signer)
	if err != nil {
		t.Fatalf("NewPassportFromData() failed: %v", err)
	}
	passport := &Passport{
		Access: access,
		Visas:  []*Visa{visa0},
	}

	if err := policy.Test(ctx, passport); err == nil {
		t.Fatal("policy.Test(passport) should fail.")
	}
}
