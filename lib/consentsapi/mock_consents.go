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

// Package consentsapi contains a service manages user's remembered consent
package consentsapi

import (
	"context"
	"net/http"

	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/golang/protobuf/ptypes" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */

	glog "github.com/golang/glog" /* copybara-comment */
	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
	tgpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/consents/v1" /* copybara-comment: consents_go_grpc_proto */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/consents/v1" /* copybara-comment: consents_go_proto */
)

// MockConsentsHandler is a HTTP handler wrapping a GRPC server.
type MockConsentsHandler struct {
	s tgpb.ConsentsServer
}

// NewMockConsentsHandler returns a new MockConsentsHandler.
func NewMockConsentsHandler(s tgpb.ConsentsServer) *MockConsentsHandler {
	return &MockConsentsHandler{s: s}
}

// DeleteConsent handles DeleteConsent HTTP requests.
func (h *MockConsentsHandler) DeleteConsent(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user"]
	consentID := mux.Vars(r)["id"]

	req := &cpb.DeleteConsentRequest{UserId: userID, ConsentId: consentID}
	_, err := h.s.MockDeleteConsent(r.Context(), req)
	if err != nil {
		httputils.WriteError(w, err)
	}
}

// ListConsents handles ListConsents HTTP requests.
func (h *MockConsentsHandler) ListConsents(w http.ResponseWriter, r *http.Request) {
	userID := mux.Vars(r)["user"]

	req := &cpb.ListConsentsRequest{UserId: userID}
	resp, err := h.s.MockListConsents(r.Context(), req)
	if err != nil {
		httputils.WriteError(w, err)
	}
	httputils.WriteResp(w, resp)
}

// StubConsents is a stub implementation.
type StubConsents struct {
	Consent *cpb.MockConsent
}

// DeleteConsent revokes a consent.
func (s *StubConsents) DeleteConsent(_ context.Context, req *cpb.DeleteConsentRequest) (*epb.Empty, error) {
	return &epb.Empty{}, nil
}

// ListConsents lists the consents.
func (s *StubConsents) ListConsents(_ context.Context, req *cpb.ListConsentsRequest) (*cpb.ListConsentsResponse, error) {
	return nil, nil
}

// MockDeleteConsent revokes a consent.
func (s *StubConsents) MockDeleteConsent(_ context.Context, req *cpb.DeleteConsentRequest) (*epb.Empty, error) {
	glog.Infof("DeleteConsent %v", req)
	return &epb.Empty{}, nil
}

// MockListConsents lists the consents.
func (s *StubConsents) MockListConsents(_ context.Context, req *cpb.ListConsentsRequest) (*cpb.MockListConsentsResponse, error) {
	glog.Infof("ListConsents %v", req)
	return &cpb.MockListConsentsResponse{Consents: []*cpb.MockConsent{s.Consent}}, nil
}

// FakeConsent is a fake consent.
// TODO: move these fakes to test file once implemented.
var FakeConsent = &cpb.MockConsent{
	Name:       "consents/fake-consent",
	User:       "fake-user",
	Client:     "fake-client",
	Items:      []string{"fake-visa-1", "fake-visa-2", "fake-visa-3"},
	Scopes:     []string{"fake-scope-1", "fake-scope-2"},
	Resouces:   []string{"fake-resource-1", "fake-resource-2"},
	CreateTime: ptypes.TimestampNow(),
	UpdateTime: ptypes.TimestampNow(),
}
