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

package faketokensapi

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/jsonutil" /* copybara-comment: jsonutil */

	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1" /* copybara-comment: go_proto */
)

func TestGetToken(t *testing.T) {
	ts := NewTokensHandler(&StubTokens{Token: FakeToken})
	s := httptest.NewServer(http.HandlerFunc(ts.GetToken))
	defer s.Close()

	name := "/tokens/token-id"
	resp, err := s.Client().Get(s.URL + name)
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetToken failed: %v", resp.Status)
	}

	got := &tpb.Token{}
	httputils.MustDecodeJSONPBResp(t, resp, got)

	want := FakeToken
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetToken(%s) returned diff (-want +got):\n%s", name, diff)
	}
}

func TestListTokens(t *testing.T) {
	ts := NewTokensHandler(&StubTokens{Token: FakeToken})
	s := httptest.NewServer(http.HandlerFunc(ts.ListTokens))
	defer s.Close()

	name := "/tokens"
	resp, err := s.Client().Get(s.URL + name)
	if err != nil {
		t.Fatalf("ListTokens failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("ListTokens failed: %v", resp.Status)
	}

	got := &tpb.ListTokensResponse{}
	httputils.MustDecodeJSONPBResp(t, resp, got)

	want := &tpb.ListTokensResponse{Tokens: []*tpb.Token{FakeToken}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("ListTokens(%s) returned diff (-want +got):\n%s", name, diff)
	}
}

func TestTokenJSONFormat(t *testing.T) {
	ts := NewTokensHandler(&StubTokens{Token: FakeToken})
	s := httptest.NewServer(http.HandlerFunc(ts.GetToken))
	defer s.Close()

	name := "/tokens/token-id"
	resp, err := s.Client().Get(s.URL + name)
	if err != nil {
		t.Fatalf("GetToken failed: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GetToken failed: %v", resp.Status)
	}

	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("ioutil.ReadAll(_) failed: %v", err)
	}
	got := string(b)

	want := fakeTokenJSON
	if diff := cmp.Diff(jsonutil.MustCanonical(want), jsonutil.MustCanonical(got)); diff != "" {
		t.Errorf("Token JSON diff (-want +got):\n%s", diff)
	}
}
