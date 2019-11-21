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

package ic

import (
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/jsonutil"

	tpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/tokens/v1"
)

var fakeToken = &tpb.Token{
	Name:      "fake-token",
	IssuedAt:  1573850929,
	ExpiresAt: 1573847329,
	Scope:     "fake-scope",
	Client: &tpb.Client{
		Id:          "fake-client-id",
		Name:        "fake-client-name",
		Description: "fake-client-description",
	},
	Target: "fake-target",
	Metadata: map[string]string{
		"client_desc": "fake-client-ui-description",
	},
}

const fakeTokenJSON = `{
  "client": {
    "description": "fake-client-description",
    "id": "fake-client-id",
    "name": "fake-client-name"
  },
  "expires_at": 1573847329,
  "issued_at": 1573850929,
  "metadata": {
    "client_desc": "fake-client-ui-description"
  },
  "name": "fake-token",
  "scope": "fake-scope",
  "target": "fake-target"
}`

func TestGetToken(t *testing.T) {
	ts := NewTokensHandler(&stubTokens{token: fakeToken})
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
	httputil.MustDecodeRPCResp(t, resp, got)

	want := fakeToken
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("GetToken(%s) returned diff (-want +got):\n%s", name, diff)
	}
}

func TestListTokens(t *testing.T) {
	ts := NewTokensHandler(&stubTokens{token: fakeToken})
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
	httputil.MustDecodeRPCResp(t, resp, got)

	want := &tpb.ListTokensResponse{Tokens: []*tpb.Token{fakeToken}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Errorf("ListTokens(%s) returned diff (-want +got):\n%s", name, diff)
	}
}

func TestTokenJSONFormat(t *testing.T) {
	ts := NewTokensHandler(&stubTokens{token: fakeToken})
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
