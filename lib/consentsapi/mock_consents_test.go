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

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/consents/v1" /* copybara-comment: consents_go_proto */
)

func TestListConsents(t *testing.T) {
	ts := NewMockConsentsHandler(&StubConsents{Consent: FakeConsent})
	s := httptest.NewServer(http.HandlerFunc(ts.ListConsents))
	defer s.Close()

	name := "/consents"
	resp, err := s.Client().Get(s.URL + name)
	if err != nil {
		t.Fatalf("ListConsents failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListConsents failed: %v", resp.Status)
	}

	got := &cpb.MockListConsentsResponse{}
	httputils.MustDecodeJSONPBResp(t, resp, got)

	want := &cpb.MockListConsentsResponse{Consents: []*cpb.MockConsent{FakeConsent}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("ListConsents(%s) returned diff (-want +got):\n%s", name, diff)
	}
}
