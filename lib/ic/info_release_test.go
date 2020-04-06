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

package ic

import (
	"bytes"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/golang/protobuf/jsonpb" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/fakeencryption" /* copybara-comment: fakeencryption */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakehydra" /* copybara-comment: fakehydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	glog "github.com/golang/glog" /* copybara-comment */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
	cspb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/consents" /* copybara-comment: go_proto */
)

var (
	visa1 = &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer: "issuer-1",
		},
		Assertion: ga4gh.Assertion{
			By:     "by-1",
			Type:   "type-1",
			Value:  "value-1",
			Source: "source-1",
		},
	}

	visa2 = &ga4gh.VisaData{
		StdClaims: ga4gh.StdClaims{
			Issuer: "issuer-2",
		},
		Assertion: ga4gh.Assertion{
			By:     "by-2",
			Type:   "type-2",
			Value:  "value-2",
			Source: "source-2",
		},
	}
)

func Test_toInformationReleasePageArgs(t *testing.T) {
	v, err := ga4gh.NewVisaFromData(visa1, "", ga4gh.RS256, testkeys.Default.Private, testkeys.Default.ID)
	if err != nil {
		t.Fatalf("NewVisaFromData(_) failed: %v", err)
	}
	id := &ga4gh.Identity{
		Subject: "sub",
		Name:    "name-1",
		Email:   "a@example.com",
		Identities: map[string][]string{
			"a@example.org": nil,
		},
		VisaJWTs: []string{string(v.JWT())},
	}

	t.Run("default", func(t *testing.T) {
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline ga4gh_passport_v1 profile identities account_admin")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline ga4gh_passport_v1 profile identities account_admin",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information: map[string][]*informationItem{
				"Permission": []*informationItem{
					{
						Title: "account_admin",
						Value: "manage (modify) this account",
						ID:    "account_admin",
					},
				},
				"Profile": []*informationItem{
					{Title: "Name", Value: "name-1", ID: "profile.name"},
					{Title: "Email", Value: "a@example.com", ID: "profile.email"},
					{Title: "Identities", Value: "a@example.org", ID: "identities"},
				},
				"Visas": []*informationItem{
					{
						Title: "type-1@source-1",
						Value: "value-1",
						ID:    "eyJ0eXBlIjoidHlwZS0xIiwic291cmNlIjoic291cmNlLTEiLCJieSI6ImJ5LTEiLCJpc3MiOiJpc3N1ZXItMSJ9",
					},
				},
			},
			State: "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})

	t.Run("less scope", func(t *testing.T) {
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information:     map[string][]*informationItem{},
			State:           "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})

	t.Run("less info", func(t *testing.T) {
		id := &ga4gh.Identity{
			Subject: "sub",
		}
		got := toInformationReleasePageArgs(id, "state", "client", "openid offline ga4gh_passport_v1 profile identities")
		want := &informationReleasePageArgs{
			ApplicationName: "client",
			Scope:           "openid offline ga4gh_passport_v1 profile identities",
			AssetDir:        "/identity/static",
			ID:              "sub",
			Offline:         true,
			Information:     map[string][]*informationItem{},
			State:           "state",
		}
		if d := cmp.Diff(want, got); len(d) != 0 {
			t.Errorf("toInformationReleasePageArgs (-want, +got): %s", d)
		}
	})
}

func Test_toRememberedConsentPreference(t *testing.T) {
	tests := []struct {
		name     string
		postKeys []string
		remember cspb.RememberedConsentPreference_RequestMatchType
		want     *cspb.RememberedConsentPreference
		wantErr  bool
	}{
		{
			name: "default",
			postKeys: []string{
				"profile.name",
				"profile.email",
				"profile.others",
				"account_admin",
				"link",
				"identities",
				ga4ghVisaToSelectedVisaPostKey(visa1),
				ga4ghVisaToSelectedVisaPostKey(visa2),
			},
			remember: cspb.RememberedConsentPreference_SUBSET,
			want: &cspb.RememberedConsentPreference{
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
				ReleaseIdentities:   true,
				RequestMatchType:    cspb.RememberedConsentPreference_SUBSET,
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				SelectedVisas: []*cspb.RememberedConsentPreference_Visa{
					ga4ghVisaToSelectedVisa(visa1),
					ga4ghVisaToSelectedVisa(visa2),
				},
			},
		},
		{
			name:     "remember-any",
			postKeys: []string{},
			remember: cspb.RememberedConsentPreference_ANYTHING,
			want: &cspb.RememberedConsentPreference{
				RequestMatchType: cspb.RememberedConsentPreference_ANYTHING,
				ReleaseType:      cspb.RememberedConsentPreference_SELECTED,
			},
		},
		{
			name:     "remember-none",
			postKeys: []string{},
			remember: cspb.RememberedConsentPreference_NONE,
			want: &cspb.RememberedConsentPreference{
				RequestMatchType: cspb.RememberedConsentPreference_NONE,
				ReleaseType:      cspb.RememberedConsentPreference_SELECTED,
			},
		},
		{
			name: "release-any",
			postKeys: []string{
				"select-anything",
			},
			remember: cspb.RememberedConsentPreference_NONE,
			want: &cspb.RememberedConsentPreference{
				RequestMatchType: cspb.RememberedConsentPreference_NONE,
				ReleaseType:      cspb.RememberedConsentPreference_ANYTHING_NEEDED,
			},
		},
		{
			name: "invalid key",
			postKeys: []string{
				"invalid",
			},
			remember: cspb.RememberedConsentPreference_NONE,
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			q := url.Values{}
			for _, k := range tc.postKeys {
				q.Set(k, "yes")
			}
			switch tc.remember {
			case cspb.RememberedConsentPreference_NONE:
				q.Set("remember", "remember-none")
			case cspb.RememberedConsentPreference_SUBSET:
				q.Set("remember", "remember-samesubset")
			case cspb.RememberedConsentPreference_ANYTHING:
				q.Set("remember", "remember-any")
			}
			r := httptest.NewRequest(http.MethodPost, "/", bytes.NewBufferString(q.Encode()))
			r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			r.ParseForm()
			got, err := toRememberedConsentPreference(r)
			if err == nil && tc.wantErr {
				t.Errorf("toRememberedConsentPreference() wants err")
			}
			if err != nil && !tc.wantErr {
				t.Errorf("toRememberedConsentPreference() failed: %v", err)
			}
			if tc.wantErr {
				return
			}

			got.CreateTime = nil
			got.ExpireTime = nil
			sort.Slice(got.SelectedVisas, func(i int, j int) bool {
				return got.SelectedVisas[i].Type < got.SelectedVisas[j].Type
			})
			sort.Slice(tc.want.SelectedVisas, func(i int, j int) bool {
				return tc.want.SelectedVisas[i].Type < tc.want.SelectedVisas[j].Type
			})
			if d := cmp.Diff(tc.want, got, protocmp.Transform()); len(d) > 0 {
				t.Errorf("toRememberedConsentPreference() (-want, +got): %v", d)
			}
		})
	}
}

func ga4ghVisaToSelectedVisaPostKey(d *ga4gh.VisaData) string {
	rcp := ga4ghVisaToSelectedVisa(d)
	marshaler := jsonpb.Marshaler{}
	ss, err := marshaler.MarshalToString(rcp)
	if err != nil {
		glog.Fatalf("MarshalToString() failed: %v", err)
	}

	return base64.StdEncoding.EncodeToString([]byte(ss))
}

func ga4ghVisaToSelectedVisa(d *ga4gh.VisaData) *cspb.RememberedConsentPreference_Visa {
	return &cspb.RememberedConsentPreference_Visa{
		Iss:    d.Issuer,
		Type:   string(d.Assertion.Type),
		Source: string(d.Assertion.Source),
		By:     string(d.Assertion.By),
	}
}

func Test_scopedIdentity(t *testing.T) {
	v1, err := ga4gh.NewVisaFromData(visa1, "", ga4gh.RS256, testkeys.Default.Private, testkeys.Default.ID)
	if err != nil {
		t.Fatalf("NewVisaFromData(_) failed: %v", err)
	}
	v2, err := ga4gh.NewVisaFromData(visa2, "", ga4gh.RS256, testkeys.Default.Private, testkeys.Default.ID)
	if err != nil {
		t.Fatalf("NewVisaFromData(_) failed: %v", err)
	}
	id := &ga4gh.Identity{
		Subject: "sub",
		Name:    "name-1",
		Email:   "a@example.com",
		Identities: map[string][]string{
			"a@example.org": nil,
		},
		Picture:  "https://example.com/pic",
		VisaJWTs: []string{string(v1.JWT()), string(v2.JWT())},
	}

	iss := "https://example.com"
	subject := "sub-1"
	iat := int64(100)
	nbf := int64(0)
	exp := int64(10000)

	tests := []struct {
		name  string
		rcp   *cspb.RememberedConsentPreference
		scope string
		want  *ga4gh.Identity
	}{
		{
			name: "select anything",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType: cspb.RememberedConsentPreference_ANYTHING_NEEDED,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture:   "https://example.com/pic",
				VisaJWTs:  []string{string(v1.JWT()), string(v2.JWT())},
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "less scope",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType: cspb.RememberedConsentPreference_ANYTHING_NEEDED,
			},
			scope: "openid offline ga4gh_passport_v1 identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				VisaJWTs:  []string{string(v1.JWT()), string(v2.JWT())},
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 identities link account_admin",
			},
		},
		{
			name: "select consent: select none",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType: cspb.RememberedConsentPreference_SELECTED,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject:   "sub-1",
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities",
			},
		},
		{
			name: "select consent: select all",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
				SelectedVisas: []*cspb.RememberedConsentPreference_Visa{
					ga4ghVisaToSelectedVisa(visa1), ga4ghVisaToSelectedVisa(visa2),
				},
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture: "https://example.com/pic",

				VisaJWTs:  []string{string(v1.JWT()), string(v2.JWT())},
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "select consent: no name",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  false,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture: "https://example.com/pic",

				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "select consent: no email",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: false,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture:   "https://example.com/pic",
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "select consent: no profile other",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: false,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "select consent: no identities",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   false,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject:   "sub-1",
				Name:      "name-1",
				Email:     "a@example.com",
				Picture:   "https://example.com/pic",
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "select consent: no account_admin",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: false,
				ReleaseLink:         true,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture:   "https://example.com/pic",
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link",
			},
		},
		{
			name: "select consent: no link",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         false,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture:   "https://example.com/pic",
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities account_admin",
			},
		},
		{
			name: "select consent: no visa",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture:   "https://example.com/pic",
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
		{
			name: "select consent: select visa",
			rcp: &cspb.RememberedConsentPreference{
				ReleaseType:         cspb.RememberedConsentPreference_SELECTED,
				ReleaseProfileName:  true,
				ReleaseProfileEmail: true,
				ReleaseProfileOther: true,
				ReleaseIdentities:   true,
				ReleaseAccountAdmin: true,
				ReleaseLink:         true,
				SelectedVisas:       []*cspb.RememberedConsentPreference_Visa{ga4ghVisaToSelectedVisa(visa1)},
			},
			scope: "openid offline ga4gh_passport_v1 profile identities link account_admin",
			want: &ga4gh.Identity{
				Subject: "sub-1",
				Name:    "name-1",
				Email:   "a@example.com",
				Identities: map[string][]string{
					"a@example.org": nil,
				},
				Picture:   "https://example.com/pic",
				VisaJWTs:  []string{string(v1.JWT())},
				Issuer:    iss,
				IssuedAt:  iat,
				NotBefore: nbf,
				Expiry:    exp,
				Scope:     "openid offline ga4gh_passport_v1 profile identities link account_admin",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := scopedIdentity(id, tc.rcp, tc.scope, iss, subject, iat, nbf, exp)
			got.ID = ""
			if err != nil {
				t.Fatalf("scopedIdentity(%+v, %+v, %s, _) failed: %v", id, tc.rcp, tc.scope, err)
			}
			if d := cmp.Diff(tc.want, got); len(d) > 0 {
				t.Errorf("scopedIdentity(%+v, %+v, %s, _) (-want, +got): %s", id, tc.rcp, tc.scope, d)
			}
		})
	}
}

func sendAcceptInformationRelease(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, scope, stateID string, remember cspb.RememberedConsentPreference_RequestMatchType) (*http.Response, error) {
	// Ensure auth token state exists before request.
	tokState := &cpb.LoginState{
		Realm:            storage.DefaultRealm,
		Scope:            scope,
		ConsentChallenge: consentChallenge,
		Subject:          LoginSubject,
	}

	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, authTokenStateID, storage.LatestRev, tokState, nil)
	if err != nil {
		return nil, err
	}

	// Ensure identity exists before request.
	acct := &cpb.Account{
		Properties: &cpb.AccountProperties{Subject: LoginSubject},
		State:      "ACTIVE",
		ConnectedAccounts: []*cpb.ConnectedAccount{
			{
				Properties: &cpb.AccountProperties{
					Subject: "foo@bar.com",
				},
			},
		},
	}
	err = s.store.Write(storage.AccountDatatype, storage.DefaultRealm, storage.DefaultUser, LoginSubject, storage.LatestRev, acct, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}
	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := url.Values{}
	query.Set("state", stateID)
	query.Set("select-anything", "yes")
	if remember == cspb.RememberedConsentPreference_ANYTHING {
		query.Set("remember", "remember-any")
	} else if remember == cspb.RememberedConsentPreference_SUBSET {
		query.Set("remember", "remember-samesubset")
	} else if remember == cspb.RememberedConsentPreference_NONE {
		query.Set("remember", "remember-none")
	}
	u := "https://" + domain + acceptInformationReleasePath
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, u, bytes.NewBufferString(query.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func sendRejectInformationRelease(s *Service, cfg *pb.IcConfig, h *fakehydra.Server, scope, stateID string) (*http.Response, error) {
	// Ensure auth token state exists before request.
	tokState := &cpb.LoginState{
		Realm:            storage.DefaultRealm,
		Scope:            scope,
		ConsentChallenge: consentChallenge,
		Subject:          LoginSubject,
	}

	err := s.store.Write(storage.LoginStateDatatype, storage.DefaultRealm, storage.DefaultUser, authTokenStateID, storage.LatestRev, tokState, nil)
	if err != nil {
		return nil, err
	}

	// Ensure identity exists before request.
	acct := &cpb.Account{
		Properties: &cpb.AccountProperties{Subject: LoginSubject},
		State:      "ACTIVE",
		ConnectedAccounts: []*cpb.ConnectedAccount{
			{
				Properties: &cpb.AccountProperties{
					Subject: "foo@bar.com",
				},
			},
		},
	}
	err = s.store.Write(storage.AccountDatatype, storage.DefaultRealm, storage.DefaultUser, LoginSubject, storage.LatestRev, acct, nil)
	if err != nil {
		return nil, err
	}

	// Clear fakehydra server and set reject response.
	h.Clear()
	h.AcceptConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}
	h.RejectConsentResp = &hydraapi.RequestHandlerResponse{RedirectTo: hydraURL}

	// Send Request.
	query := url.Values{}
	query.Set("state", stateID)
	u := "https://" + domain + rejectInformationReleasePath
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPost, u, bytes.NewBufferString(query.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	s.Handler.ServeHTTP(w, r)

	return w.Result(), nil
}

func TestAcceptInformationRelease_Hydra_Accept(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, cspb.RememberedConsentPreference_NONE)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	email, ok := h.AcceptConsentReq.Session.IDToken["email"].(string)
	if !ok {
		t.Fatalf("Email in id token in wrong type")
	}

	wantEmail := LoginSubject + "@" + domain
	if email != wantEmail {
		t.Errorf("Email in id token wants %s got %s", wantEmail, email)
	}

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestAcceptInformationRelease_Hydra_Accept_Scoped(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, cspb.RememberedConsentPreference_NONE)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	if _, ok := h.AcceptConsentReq.Session.IDToken["email"]; ok {
		t.Fatalf("Email in id token should not exists")
	}

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestAcceptInformationRelease_Hydra_Accept_Remember(t *testing.T) {
	tests := []struct {
		name          string
		remember      cspb.RememberedConsentPreference_RequestMatchType
		consentStored bool
	}{
		{
			name:          "not remember",
			remember:      cspb.RememberedConsentPreference_NONE,
			consentStored: false,
		},
		{
			name:          "remember for subset",
			remember:      cspb.RememberedConsentPreference_SUBSET,
			consentStored: true,
		},
		{
			name:          "remember for anything",
			remember:      cspb.RememberedConsentPreference_ANYTHING,
			consentStored: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s, cfg, _, h, _, err := setupHydraTest()
			if err != nil {
				t.Fatalf("setupHydraTest() failed: %v", err)
			}

			const scope = "openid"
			resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, tc.remember)
			if err != nil {
				t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
			}

			if resp.StatusCode != http.StatusSeeOther {
				t.Fatalf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
			}

			content := make(map[string]map[string]proto.Message)
			count, _ := s.store.MultiReadTx(storage.RememberedConsentDatatype, storage.DefaultRealm, LoginSubject, nil, 0, 1000, content, &cspb.RememberedConsentPreference{}, nil)
			if count == 0 {
				if tc.consentStored {
					t.Errorf("consent should store in storage")
				} else {
					return
				}
			}

			if !tc.consentStored {
				t.Errorf("consent should not store in storage")
			}
		})
	}
}

func TestAcceptInformationRelease_Hydra_Reject(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendRejectInformationRelease(s, cfg, h, scope, authTokenStateID)
	if err != nil {
		t.Fatalf("sendRejectInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.AcceptConsentReq != nil {
		t.Errorf("AcceptConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if h.RejectConsentReq == nil {
		t.Errorf("RejectConsentReq got nil")
	}
}

func TestAcceptInformationRelease_Hydra_Endpoint(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile identities"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, authTokenStateID, cspb.RememberedConsentPreference_NONE)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, %s) failed: %v", scope, authTokenStateID, err)
	}

	if resp.StatusCode != http.StatusSeeOther {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusSeeOther, resp.StatusCode)
	}

	if l := resp.Header.Get("Location"); l != hydraURL {
		t.Errorf("resp.Location wants %s got %s", hydraURL, l)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}

	if diff := cmp.Diff(h.AcceptConsentReq.GrantedScope, strings.Split(scope, " ")); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope wants %s got %v", scope, h.AcceptConsentReq.GrantedScope)
	}

	want := []interface{}{"foo@bar.com"}
	if diff := cmp.Diff(want, h.AcceptConsentReq.Session.AccessToken["identities"]); len(diff) != 0 {
		t.Errorf("AcceptConsentReq.GrantedScope (-wants, +got) %s", diff)
	}

	atid, ok := h.AcceptConsentReq.Session.AccessToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in access token in wrong type")
	}

	itid, ok := h.AcceptConsentReq.Session.IDToken["tid"].(string)
	if !ok {
		t.Fatalf("tid in id token in wrong type")
	}

	if itid != atid {
		t.Errorf("tid in id token and access token should be the same, %s, %s", itid, atid)
	}
}

func TestAcceptInformationRelease_Hydra_InvalidState(t *testing.T) {
	s, cfg, _, h, _, err := setupHydraTest()
	if err != nil {
		t.Fatalf("setupHydraTest() failed: %v", err)
	}

	const scope = "openid profile"

	resp, err := sendAcceptInformationRelease(s, cfg, h, scope, "invalid", cspb.RememberedConsentPreference_NONE)
	if err != nil {
		t.Fatalf("sendAcceptInformationRelease(s, cfg, h, %s, 'invalid') failed: %v", scope, err)
	}

	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("resp.StatusCode wants %d got %d", http.StatusInternalServerError, resp.StatusCode)
	}

	if h.AcceptConsentReq != nil {
		t.Errorf("AcceptConsentReq wants nil got %v", h.AcceptConsentReq)
	}

	if h.RejectConsentReq != nil {
		t.Errorf("RejectConsentReq wants nil got %v", h.RejectConsentReq)
	}
}

func setupForFindRememberedConsentsByUser() *Service {
	store := storage.NewMemoryStorage("ic-min", "testdata/config")

	s := NewService(&Options{
		Domain:         domain,
		ServiceName:    "ic",
		AccountDomain:  domain,
		Store:          store,
		Encryption:     fakeencryption.New(),
		UseHydra:       useHydra,
		HydraAdminURL:  hydraAdminURL,
		HydraPublicURL: hydraURL,
		HydraSyncFreq:  time.Nanosecond,
	})

	return s
}

func Test_findRememberedConsentsByUser(t *testing.T) {
	s := setupForFindRememberedConsentsByUser()

	rcps := map[string]*cspb.RememberedConsentPreference{
		"expired": {
			ClientName: "cli",
			ExpireTime: timeutil.TimestampProto(time.Time{}),
		},
		"other-cli": {
			ClientName: "other",
			ExpireTime: timeutil.TimestampProto(time.Now().Add(time.Hour)),
		},
		"want-1": {
			ClientName: "cli",
			ExpireTime: timeutil.TimestampProto(time.Now().Add(time.Hour)),
		},
		"want-2": {
			ClientName: "cli",
			ExpireTime: timeutil.TimestampProto(time.Now().Add(time.Hour)),
		},
	}

	for k, v := range rcps {
		err := s.store.Write(storage.RememberedConsentDatatype, storage.DefaultRealm, LoginSubject, k, storage.LatestRev, v, nil)
		if err != nil {
			t.Fatalf("Write RememberedConsentDatatype failed: %v", err)
		}
	}

	// Ensure expired and different client got filtered.
	got, err := s.findRememberedConsentsByUser(LoginSubject, storage.DefaultRealm, "cli", 0, maxRememberedConsent, nil)
	if err != nil {
		t.Fatalf("findRememberedConsentsByUser() failed: %v", err)
	}

	want := map[string]*cspb.RememberedConsentPreference{
		"want-1": rcps["want-1"],
		"want-2": rcps["want-2"],
	}

	if d := cmp.Diff(want, got, protocmp.Transform()); len(d) > 0 {
		t.Errorf("findRememberedConsentsByUser() (-want,+got): %s", d)
	}
}

func Test_findRememberedConsent(t *testing.T) {
	expired := &cspb.RememberedConsentPreference{
		ClientName: "cli",
		ExpireTime: timeutil.TimestampProto(time.Time{}),
	}
	anything := &cspb.RememberedConsentPreference{
		ClientName:       "cli",
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_ANYTHING,
	}
	scopeA1 := &cspb.RememberedConsentPreference{
		ClientName:       "cli",
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_SUBSET,
		RequestedScopes:  []string{"a1"},
	}
	scopeA1A2 := &cspb.RememberedConsentPreference{
		ClientName:       "cli",
		ExpireTime:       timeutil.TimestampProto(time.Now().Add(time.Hour)),
		RequestMatchType: cspb.RememberedConsentPreference_SUBSET,
		RequestedScopes:  []string{"a1", "a2"},
	}

	tests := []struct {
		name           string
		remembered     map[string]*cspb.RememberedConsentPreference
		requestedScope []string
		want           *cspb.RememberedConsentPreference
	}{
		{
			name:           "no RememberedConsent",
			requestedScope: []string{"a1", "a2"},
			want:           nil,
		},
		{
			name: "expired RememberedConsent",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired": expired,
			},
			requestedScope: []string{"a1", "a2"},
			want:           nil,
		},
		{
			name: "select anything",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired":  expired,
				"anything": anything,
				"a1a2":     scopeA1A2,
				"a1":       scopeA1,
			},
			requestedScope: []string{"a1", "a2"},
			want:           anything,
		},
		{
			name: "same scope",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired": expired,
				"a1a2":    scopeA1A2,
				"a1":      scopeA1,
			},
			requestedScope: []string{"a1", "a2"},
			want:           scopeA1A2,
		},
		{
			name: "subset scope",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired": expired,
				"a1a2":    scopeA1A2,
			},
			requestedScope: []string{"a1", "a2", "a3"},
			want:           scopeA1A2,
		},
		{
			name: "no match",
			remembered: map[string]*cspb.RememberedConsentPreference{
				"expired": expired,
				"a1a2":    scopeA1A2,
				"a1":      scopeA1,
			},
			requestedScope: []string{"a2"},
			want:           nil,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			store := storage.NewMemoryStorage("ic-min", "testdata/config")

			s := NewService(&Options{
				Domain:         domain,
				ServiceName:    "ic",
				AccountDomain:  domain,
				Store:          store,
				Encryption:     fakeencryption.New(),
				UseHydra:       useHydra,
				HydraAdminURL:  hydraAdminURL,
				HydraPublicURL: hydraURL,
				HydraSyncFreq:  time.Nanosecond,
			})

			for k, v := range tc.remembered {
				err := s.store.Write(storage.RememberedConsentDatatype, storage.DefaultRealm, LoginSubject, k, storage.LatestRev, v, nil)
				if err != nil {
					t.Fatalf("Write RememberedConsentDatatype failed: %v", err)
				}
			}

			got, err := s.findRememberedConsent(tc.requestedScope, LoginSubject, storage.DefaultRealm, "cli", nil)
			if err != nil {
				t.Fatalf("findRememberedConsent failed: %v", err)
			}

			if d := cmp.Diff(tc.want, got, protocmp.Transform()); len(d) > 0 {
				t.Errorf("findRememberedConsent() (-want,+got): %s", d)
			}
		})
	}
}
