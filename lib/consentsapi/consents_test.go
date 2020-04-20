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

package consentsapi

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/gorilla/mux" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/test/fakestore" /* copybara-comment: fakestore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	cspb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/consents/v1" /* copybara-comment: consents_go_proto */
	storepb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/consents" /* copybara-comment: go_proto */
)

func TestListConsents(t *testing.T) {
	stub := &stub{}
	store := fakestore.New()

	handler := handlerfactory.MakeHandler(store, ListConsentsFactory(&Service{
		Store:                        store,
		FindRememberedConsentsByUser: stub.findRememberedConsentsByUser,
		Clients:                      stub.clients,
	}, "/identity/v1alpha/{realm}/users/{user}/consents"))

	time1 := timeutil.TimestampProto(time.Time{}.Add(100 * time.Hour))
	time2 := timeutil.TimestampProto(time.Time{}.Add(200 * time.Hour))
	consents := map[string]*storepb.RememberedConsentPreference{
		"c1": {
			ClientName:         "cli1",
			CreateTime:         time1,
			ExpireTime:         time1,
			RequestMatchType:   storepb.RememberedConsentPreference_SUBSET,
			RequestedResources: []string{"r1", "r2"},
			RequestedScopes:    []string{"s1", "s2"},
			ReleaseType:        storepb.RememberedConsentPreference_SELECTED,
			SelectedVisas: []*storepb.RememberedConsentPreference_Visa{
				{
					Type:   "ty1",
					Source: "src1",
					By:     "by1",
					Iss:    "iss1",
				},
			},
			ReleaseProfileName:  true,
			ReleaseProfileEmail: true,
			ReleaseProfileOther: true,
			ReleaseAccountAdmin: true,
			ReleaseLink:         true,
			ReleaseIdentities:   true,
		},
		"c2": {
			ClientName:         "cli2",
			CreateTime:         time2,
			ExpireTime:         time2,
			RequestMatchType:   storepb.RememberedConsentPreference_ANYTHING,
			RequestedResources: []string{"r1", "r2"},
			RequestedScopes:    []string{"s1", "s2"},
			ReleaseType:        storepb.RememberedConsentPreference_ANYTHING_NEEDED,
		},
	}
	clients := map[string]*cpb.Client{
		"cli1": {
			ClientId: "1",
			Ui: map[string]string{
				"name": "client 1",
			},
		},
		"cli2": {
			ClientId: "2",
			Ui: map[string]string{
				"name": "client 2",
			},
		},
	}

	tests := []struct {
		name     string
		consents map[string]*storepb.RememberedConsentPreference
		clients  map[string]*cpb.Client
		want     *cspb.ListConsentsResponse
	}{
		{
			name:     "default",
			consents: consents,
			clients:  clients,
			want: &cspb.ListConsentsResponse{
				Consents: []*cspb.Consent{
					{
						Name: "users/user1/consents/c2",
						Client: &cspb.Consent_Client{
							ClientId: "2",
							Name:     "cli2",
							Ui: map[string]string{
								"name": "client 2",
							},
						},
						CreateTime:         time2,
						ExpireTime:         time2,
						RequestMatchType:   cspb.Consent_ANYTHING,
						RequestedResources: []string{"r1", "r2"},
						RequestedScopes:    []string{"s1", "s2"},
						ReleaseType:        cspb.Consent_ANYTHING_NEEDED,
					},
					{
						Name: "users/user1/consents/c1",
						Client: &cspb.Consent_Client{
							ClientId: "1",
							Name:     "cli1",
							Ui: map[string]string{
								"name": "client 1",
							},
						},
						CreateTime:         time1,
						ExpireTime:         time1,
						RequestMatchType:   cspb.Consent_SUBSET,
						RequestedResources: []string{"r1", "r2"},
						RequestedScopes:    []string{"s1", "s2"},
						ReleaseType:        cspb.Consent_SELECTED,
						SelectedVisas: []*cspb.Consent_Visa{
							{
								Type:   "ty1",
								Source: "src1",
								By:     "by1",
								Iss:    "iss1",
							},
						},
						ReleaseProfileName:  true,
						ReleaseProfileEmail: true,
						ReleaseProfileOther: true,
						ReleaseAccountAdmin: true,
						ReleaseLink:         true,
						ReleaseIdentities:   true,
					},
				},
			},
		},
		{
			name:     "empty clients",
			consents: consents,
			clients:  nil,
			want: &cspb.ListConsentsResponse{
				Consents: []*cspb.Consent{
					{
						Name: "users/user1/consents/c2",
						Client: &cspb.Consent_Client{
							Name: "cli2",
						},
						CreateTime:         time2,
						ExpireTime:         time2,
						RequestMatchType:   cspb.Consent_ANYTHING,
						RequestedResources: []string{"r1", "r2"},
						RequestedScopes:    []string{"s1", "s2"},
						ReleaseType:        cspb.Consent_ANYTHING_NEEDED,
					},
					{
						Name: "users/user1/consents/c1",
						Client: &cspb.Consent_Client{
							Name: "cli1",
						},
						CreateTime:         time1,
						ExpireTime:         time1,
						RequestMatchType:   cspb.Consent_SUBSET,
						RequestedResources: []string{"r1", "r2"},
						RequestedScopes:    []string{"s1", "s2"},
						ReleaseType:        cspb.Consent_SELECTED,
						SelectedVisas: []*cspb.Consent_Visa{
							{
								Type:   "ty1",
								Source: "src1",
								By:     "by1",
								Iss:    "iss1",
							},
						},
						ReleaseProfileName:  true,
						ReleaseProfileEmail: true,
						ReleaseProfileOther: true,
						ReleaseAccountAdmin: true,
						ReleaseLink:         true,
						ReleaseIdentities:   true,
					},
				},
			},
		},
		{
			name:     "empty consent",
			consents: nil,
			clients:  clients,
			want:     &cspb.ListConsentsResponse{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			stub.consents = tc.consents
			stub.clis = tc.clients

			r := httptest.NewRequest(http.MethodGet, "/identity/v1alpha/masterusers/user1/consents", nil)
			r = mux.SetURLVars(r, map[string]string{
				"user":  "user1",
				"realm": "master",
			})
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			resp := w.Result()
			if resp.StatusCode != http.StatusOK {
				t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, http.StatusOK)
			}

			got := &cspb.ListConsentsResponse{}
			httputils.MustDecodeJSONPBResp(t, resp, got)

			if d := cmp.Diff(tc.want, got, protocmp.Transform()); len(d) > 0 {
				t.Errorf("ListConsents() returned diff (-want +got):\n%s", d)
			}
		})
	}
}

func TestDeleteConsent(t *testing.T) {
	stub := &stub{}

	store := fakestore.New()
	handler := handlerfactory.MakeHandler(store, DeleteConsentFactory(&Service{
		Store:                        store,
		FindRememberedConsentsByUser: stub.findRememberedConsentsByUser,
		Clients:                      stub.clients,
	}, "/identity/v1alpha/{realm}/users/{user}/consents/{consent_id}"))

	tests := []struct {
		name      string
		consentID string
		want      int
	}{
		{
			name:      "delete success",
			consentID: "consent1",
			want:      http.StatusOK,
		},
		{
			name:      "not found",
			consentID: "invalid",
			want:      http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := store.Write(storage.RememberedConsentDatatype, storage.DefaultRealm, "user1", "consent1", storage.LatestRev, &storepb.RememberedConsentPreference{}, nil); err != nil {
				t.Fatalf("Write RememberedConsentDatatype failed: %v", err)
			}

			r := httptest.NewRequest(http.MethodDelete, "/identity/v1alpha/masterusers/user1/consents/"+tc.consentID, nil)
			r = mux.SetURLVars(r, map[string]string{
				"user":       "user1",
				"realm":      "master",
				"consent_id": tc.consentID,
			})
			w := httptest.NewRecorder()
			handler.ServeHTTP(w, r)

			resp := w.Result()
			if resp.StatusCode != tc.want {
				t.Errorf("StatusCode = %d, wants %d", resp.StatusCode, tc.want)
			}
		})
	}
}

type stub struct {
	consents map[string]*storepb.RememberedConsentPreference
	clis     map[string]*cpb.Client
}

func (s *stub) findRememberedConsentsByUser(store storage.Store, subject, realm, clientName string, offset, pageSize int, tx storage.Tx) (map[string]*storepb.RememberedConsentPreference, error) {
	return s.consents, nil
}

func (s *stub) clients(tx storage.Tx) (map[string]*cpb.Client, error) {
	return s.clis, nil
}
