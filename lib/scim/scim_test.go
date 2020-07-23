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

package scim

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	spb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/scim/v2" /* copybara-comment: go_proto */
)

func TestLoadAccount(t *testing.T) {
	user := "dr_joe_elixir"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	acct, _, err := s.LoadAccount(user, realm, true, nil)
	if err != nil {
		t.Fatalf("LoadAccount(%q, %q, true, nil) failed: %v", user, realm, err)
	}
	if acct.Properties.Subject == "" {
		t.Fatalf("LoadAccount(%q, %q, true, nil) = (%+v, _, _): expected subject content to load", user, realm, acct)
	}
}

func TestLoadAccount_Error(t *testing.T) {
	user := "dr_joe_elixir"
	realm := "empty"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	_, st, err := s.LoadAccount(user, realm, true, nil)
	if err == nil {
		t.Fatalf("LoadAccount(%q, %q, true, nil) unexpected success: no account on realm %q", user, realm, realm)
	}
	if st == http.StatusOK {
		t.Fatalf("LoadAccount(%q, %q, true, nil) status code mismatch: got %d, not want %d", user, realm, st, http.StatusOK)
	}
}

func TestLoadAccountLookup(t *testing.T) {
	user := "non-admin@example.org"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	lookup, err := s.LoadAccountLookup(realm, user, nil)
	if err != nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) failed: %v", realm, user, err)
	}
	if lookup == nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) got nil lookup", realm, user)
	}
	want := "non-admin"
	if lookup.Subject != want {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) = (%+v, _, _) subject mismatch: got %q, want %q", realm, user, lookup, lookup.Subject, want)
	}
}

func TestLoadAccountLookup_Error(t *testing.T) {
	user := "no_exists@example.org"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	got, err := s.LoadAccountLookup(realm, user, nil)
	if err != nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) failed: %v", realm, user, err)
	}
	if got != nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) lookup mismatch: got %+v, want %v", realm, user, got, nil)
	}
}

func TestSaveAccountLookup(t *testing.T) {
	user := "non-admin@example.org"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	lookup := &cpb.AccountLookup{
		Subject:  "non-admin",
		Revision: 46,
		State:    "ACTIVE",
	}
	err := s.SaveAccountLookup(lookup, realm, user, nil, &ga4gh.Identity{Subject: lookup.Subject}, nil)
	if err != nil {
		t.Fatalf("SaveAccountLookup(lookup, %q, %q, nil, id, nil) failed: %v", realm, user, err)
	}
	got, err := s.LoadAccountLookup(realm, user, nil)
	if err != nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) failed: %v", realm, user, err)
	}
	if diff := cmp.Diff(lookup, got, protocmp.Transform(), cmpopts.EquateEmpty()); diff != "" {
		t.Fatalf("SaveAccountLookup mismatch (-want +got):\n%s", diff)
	}
}

func TestRemoveAccountLookup(t *testing.T) {
	user := "non-admin@example.org"
	realm := "test"
	rev := int64(48)
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	err := s.RemoveAccountLookup(rev, realm, user, nil, &ga4gh.Identity{Subject: "non-admin"}, nil)
	if err != nil {
		t.Fatalf("RemoveAccountLookup(%d, %q, %q, nil, id, nil) failed: %v", rev, realm, user, err)
	}
	got, err := s.LoadAccountLookup(realm, user, nil)
	if err != nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) failed: %v", realm, user, err)
	}
	if got == nil {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) failed to load deleted account", realm, user)
	}
	if got.State != storage.StateDeleted {
		t.Fatalf("LoadAccountLookup(%q, %q, nil) state mismatch: got %q, want %q", realm, user, got.State, storage.StateDeleted)
	}
}

func TestLookupAccount(t *testing.T) {
	user := "non-admin@example.org"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	acct, _, err := s.LookupAccount(user, realm, true, nil)
	if err != nil {
		t.Fatalf("LookupAccount(%q, %q, true, nil) failed: %v", user, realm, err)
	}
	want := "non-admin"
	if acct.Properties.Subject != want {
		t.Fatalf("LoadAccount(%q, %q, true, nil) = (%+v, _, _) subject mismatch: got %q, want %q", user, realm, acct, acct.Properties.Subject, want)
	}
}

func TestLookupAccount_Error(t *testing.T) {
	user := "non-admin@example.org"
	realm := "empty"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	_, st, err := s.LookupAccount(user, realm, true, nil)
	if err == nil {
		t.Fatalf("LookupAccount(%q, %q, true, nil) unexpected success: no account on realm %q", user, realm, realm)
	}
	if st == http.StatusOK {
		t.Fatalf("LookupAccount(%q, %q, true, nil) status code mismatch: got %d, not want %d", user, realm, st, http.StatusOK)
	}
}

func TestLoadGroup(t *testing.T) {
	groupName := "allowlisted"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	group, err := s.LoadGroup(groupName, realm, nil)
	if err != nil {
		t.Fatalf("LoadGroup(%q, %q, nil) failed: %v", groupName, realm, err)
	}
	if group == nil {
		t.Fatalf("LoadGroup(%q, %q, nil) = (%+v, _) group not found", groupName, realm, group)
	}
	want := "allowlisted"
	if group.Id != want {
		t.Fatalf("LoadGroup(%q, %q, nil) = (%+v, _) ID mismatch: got %q, want %q", groupName, realm, group, group.Id, want)
	}
}

func TestLoadGroup_NotFound(t *testing.T) {
	groupName := "not_exists"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	group, err := s.LoadGroup(groupName, realm, nil)
	if err != nil {
		t.Fatalf("LoadGroup(%q, %q, nil) failed: %v", groupName, realm, err)
	}
	if group != nil {
		t.Fatalf("LoadGroup(%q, %q, nil) = (%+v, _) expected nil group", groupName, realm, group)
	}
}

func TestLoadGroupMember(t *testing.T) {
	groupName := "allowlisted"
	memberName := "dr_joe@elixir.org"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	member, err := s.LoadGroupMember(groupName, memberName, realm, nil)
	if err != nil {
		t.Fatalf("LoadGroupMember(%q, %q, %q, nil) failed: %v", groupName, memberName, realm, err)
	}
	if member == nil {
		t.Fatalf("LoadGroupMember(%q, %q, %q, nil) = (%+v, _) group member not found", groupName, memberName, realm, member)
	}
	if member.Value != memberName {
		t.Fatalf("LoadGroupMember(%q, %q, %q, nil) = (%+v, _) value mismatch: got %q, want %q", groupName, memberName, realm, member, member.Value, memberName)
	}
}

func TestLoadGroupMember_NotFound(t *testing.T) {
	groupName := "allowlisted"
	memberName := "no_exists@faculty.example.edu"
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	member, err := s.LoadGroupMember(groupName, memberName, realm, nil)
	if err != nil {
		t.Fatalf("LoadGroupMember(%q, %q, %q, nil) failed: %v", groupName, memberName, realm, err)
	}
	if member != nil {
		t.Fatalf("LoadGroupMember(%q, %q, %q, nil) = (%+v, _) expected nil member", groupName, memberName, realm, member)
	}
}

func TestLoadGroupMembershipForUser(t *testing.T) {
	realm := "test"
	s := New(storage.NewMemoryStorage("ic-min", "testdata/config"))
	tests := []struct {
		name               string
		user               *spb.User
		resolveDisplayName bool
		want               []*spb.Attribute
	}{
		{
			name: "empty",
			user: &spb.User{},
			want: []*spb.Attribute{},
		},
		{
			name: "id only",
			user: &spb.User{Id: "dr_joe_elixir"},
			want: []*spb.Attribute{},
		},
		{
			name: "empty email entries",
			user: &spb.User{
				Id:     "dr_joe_elixir",
				Emails: []*spb.Attribute{{}, {}},
			},
			want: []*spb.Attribute{},
		},
		{
			name: "one email match",
			user: &spb.User{
				Id: "dr_joe_elixir",
				Emails: []*spb.Attribute{
					{Value: "dr_joe@faculty.example.edu"},
				},
			},
			resolveDisplayName: true,
			want: []*spb.Attribute{
				{Display: "Allowlisted Users", Value: "allowlisted", Ref: "group/allowlisted/dr_joe@faculty.example.edu"},
			},
		},
		{
			name: "two email match",
			user: &spb.User{
				Id: "dr_joe_elixir",
				Emails: []*spb.Attribute{
					{Value: "dr_joe@elixir.org"},
					{Value: "dr_joe@faculty.example.edu"},
				},
			},
			resolveDisplayName: true,
			want: []*spb.Attribute{
				{Display: "Allowlisted Users", Value: "allowlisted", Ref: "group/allowlisted/dr_joe@elixir.org"},
				{Display: "Allowlisted Users", Value: "allowlisted", Ref: "group/allowlisted/dr_joe@faculty.example.edu"},
				{Display: "Lab Members", Value: "lab", Ref: "group/lab/dr_joe@elixir.org"},
			},
		},
		{
			name: "two email match - no displayName",
			user: &spb.User{
				Id: "dr_joe_elixir",
				Emails: []*spb.Attribute{
					{Value: "dr_joe@elixir.org"},
					{Value: "dr_joe@faculty.example.edu"},
				},
			},
			resolveDisplayName: false,
			want: []*spb.Attribute{
				{Value: "allowlisted", Ref: "group/allowlisted/dr_joe@elixir.org"},
				{Value: "allowlisted", Ref: "group/allowlisted/dr_joe@faculty.example.edu"},
				{Value: "lab", Ref: "group/lab/dr_joe@elixir.org"},
			},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := s.LoadGroupMembershipForUser(tc.user, realm, tc.resolveDisplayName, nil); err != nil {
				t.Fatalf("LoadGroupMembershipForUser(_, %q, nil) failed: %v", realm, err)
			}
			got := tc.user.Groups
			if d := cmp.Diff(tc.want, got, protocmp.Transform(), cmpopts.EquateEmpty()); len(d) > 0 {
				t.Fatalf("mismatched group membership (-want +got): %v", d)
			}
		})
	}
}
