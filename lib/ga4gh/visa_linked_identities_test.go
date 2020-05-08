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

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
)

func TestLinkedIDValue(t *testing.T) {
	issuer0 := testkeys.Keys[testkeys.VisaIssuer0]
	issuer1 := testkeys.Keys[testkeys.VisaIssuer1]
	ids := []ID{
		{Issuer: issuer0.ID, Subject: "alice0"},
		{Issuer: issuer0.ID, Subject: "alice1"},
		{Issuer: issuer1.ID, Subject: "alice2"},
		{Issuer: issuer1.ID, Subject: "alice3"},
	}

	got := LinkedIDValue(ids)

	want := Value("alice0,testkeys-visa-issuer-0;alice1,testkeys-visa-issuer-0;alice2,testkeys-visa-issuer-1;alice3,testkeys-visa-issuer-1")
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("LinkedIDValue(%v) returned diff (-want +got):\n%s", ids, diff)
	}
}

func TestExtractLinkedIDs(t *testing.T) {
	issuer0 := testkeys.Keys[testkeys.VisaIssuer0]
	issuer1 := testkeys.Keys[testkeys.VisaIssuer1]
	ids := []ID{
		{Issuer: issuer0.ID, Subject: "alice0"},
		{Issuer: issuer0.ID, Subject: "alice1"},
		{Issuer: issuer1.ID, Subject: "alice2"},
		{Issuer: issuer1.ID, Subject: "alice3"},
	}

	a := newLinkedIDVisa(t, issuer0, ids[0], LinkedIDValue(ids[1:])).Data().Assertion
	got := ExtractLinkedIDs(a)

	want := ids[1:]
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ExtractLinkedIDs(%v) returned diff (-want +got):\n%s", a, diff)
	}
}

func TestExtractLinkedIDs_BadType(t *testing.T) {
	a := Assertion{Type: AffiliationAndRole}
	got := ExtractLinkedIDs(a)
	var want []ID
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ExtractLinkedIDs(%v) returned diff (-want +got):\n%s", a, diff)
	}
}

func TestExtractLinkedIDs_BadFormat(t *testing.T) {
	a := Assertion{Type: LinkedIdentities, Value: "bad;subject,issuer"}
	got := ExtractLinkedIDs(a)
	var want []ID
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ExtractLinkedIDs(%v) returned diff (-want +got):\n%s", a, diff)
	}
}

func TestExtractLinkedIDs_BadIssuerURLEscape(t *testing.T) {
	a := Assertion{Type: LinkedIdentities, Value: "subject,%%issuer"}
	got := ExtractLinkedIDs(a)
	var want []ID
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ExtractLinkedIDs(%v) returned diff (-want +got):\n%s", a, diff)
	}
}

func TestExtractLinkedIDs_BadSubjectURLEscape(t *testing.T) {
	a := Assertion{Type: LinkedIdentities, Value: "%%subject,issuer"}
	got := ExtractLinkedIDs(a)
	var want []ID
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("ExtractLinkedIDs(%v) returned diff (-want +got):\n%s", a, diff)
	}
}

func TestCheckLinkedIDs(t *testing.T) {
	// 0->1, 1->2, 2->3
	issuer0 := testkeys.Keys[testkeys.VisaIssuer0]
	issuer1 := testkeys.Keys[testkeys.VisaIssuer1]
	ids := []ID{
		{Issuer: issuer0.ID, Subject: "alice0"},
		{Issuer: issuer0.ID, Subject: "alice1"},
		{Issuer: issuer1.ID, Subject: "alice2"},
		{Issuer: issuer1.ID, Subject: "alice3"},
	}
	links := map[ID][]ID{
		ids[0]: {ids[1]},
		ids[1]: {ids[2]},
		ids[2]: {ids[3]},
		ids[3]: {},
	}
	var visas []*Visa
	for _, id := range ids {
		key := testkeys.Keys[testkeys.Component(id.Issuer)]
		visas = append(visas, newLinkedIDVisa(t, key, id, LinkedIDValue(links[id])))
	}

	if err := CheckLinkedIDs(visas); err != nil {
		t.Fatalf("CheckLinkedIDs(%v) failed: %v", visas, err)
	}
}

func TestCheckLinkedIDs_SingleID(t *testing.T) {
	key := testkeys.Keys[testkeys.VisaIssuer0]
	id := ID{Issuer: key.ID, Subject: "alice0"}
	visas := []*Visa{newLinkedIDVisa(t, key, id, LinkedIDValue(nil))}

	if err := CheckLinkedIDs(visas); err != nil {
		t.Fatalf("CheckLinkedIDs(%v) failed: %v", visas, err)
	}
}

func TestCheckLinkedIDs_ReverseOrder(t *testing.T) {
	// 1->0
	key := testkeys.Keys[testkeys.VisaIssuer0]
	ids := []ID{
		{Issuer: key.ID, Subject: "alice0"},
		{Issuer: key.ID, Subject: "alice1"},
	}
	links := map[ID][]ID{
		ids[0]: {},
		ids[1]: {ids[0]},
	}
	var visas []*Visa
	for _, id := range ids {
		key := testkeys.Keys[testkeys.Component(id.Issuer)]
		visas = append(visas, newLinkedIDVisa(t, key, id, LinkedIDValue(links[id])))
	}

	if err := CheckLinkedIDs(visas); err != nil {
		t.Fatalf("CheckLinkedIDs(%v) failed: %v", visas, err)
	}
}

func TestCheckLinkedIDs_Disconnected(t *testing.T) {
	// 0->1, 2->3
	issuer0 := testkeys.Keys[testkeys.VisaIssuer0]
	issuer1 := testkeys.Keys[testkeys.VisaIssuer1]
	ids := []ID{
		{Issuer: issuer0.ID, Subject: "alice0"},
		{Issuer: issuer0.ID, Subject: "alice1"},
		{Issuer: issuer1.ID, Subject: "alice2"},
		{Issuer: issuer1.ID, Subject: "alice3"},
	}
	links := map[ID][]ID{
		ids[0]: {ids[1]},
		ids[1]: {},
		ids[2]: {ids[3]},
		ids[3]: {},
	}
	var visas []*Visa
	for _, id := range ids {
		key := testkeys.Keys[testkeys.Component(id.Issuer)]
		visas = append(visas, newLinkedIDVisa(t, key, id, LinkedIDValue(links[id])))
	}

	if err := CheckLinkedIDs(visas); err == nil {
		t.Fatalf("CheckLinkedIDs(%v) should fail.", visas)
	}
}

func newLinkedIDVisa(t *testing.T, key testkeys.Key, id ID, value Value) *Visa {
	t.Helper()
	return newVisa(t, key, id, Assertion{Type: LinkedIdentities, Value: value}, "openid", "")
}

func newVisa(t *testing.T, key testkeys.Key, id ID, a Assertion, scope string, jku string) *Visa {
	t.Helper()
	d := &VisaData{
		StdClaims: StdClaims{
			Issuer:  id.Issuer,
			Subject: id.Subject,
		},
		Scope: Scope(scope),
		Assertion: a,
	}

	v, err := NewVisaFromData(d, jku, RS256, key.Private, key.ID)
	if err != nil {
		t.Fatalf("NewVisaFromData(%+v,%q,%v,%v,%v) failed: %v", d, jku, RS256, key.Private, key.ID, err)
	}
	return v
}
