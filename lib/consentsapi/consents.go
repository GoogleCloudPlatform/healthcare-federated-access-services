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

package consentsapi

import (
	"context"
	"net/http"

	glog "github.com/golang/glog" /* copybara-comment */
	epb "github.com/golang/protobuf/ptypes/empty" /* copybara-comment */
	"google3/net/proto2/go/ptypes"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	tgpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/consents/v1" /* copybara-comment: consents_go_grpc_proto */
	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/consents/v1" /* copybara-comment: consents_go_proto */
)

// ConsentsHandler is a HTTP handler wrapping a GRPC server.
type ConsentsHandler struct {
	s tgpb.ConsentsServer
}

// NewConsentsHandler returns a new ConsentsHandler.
func NewConsentsHandler(s tgpb.ConsentsServer) *ConsentsHandler {
	return &ConsentsHandler{s: s}
}

// DeleteConsent handles DeleteConsent HTTP requests.
func (h *ConsentsHandler) DeleteConsent(w http.ResponseWriter, r *http.Request) {
	req := &cpb.DeleteConsentRequest{Name: r.RequestURI}
	resp, err := h.s.DeleteConsent(r.Context(), req)
	if err != nil {
		httputils.WriteError(w, err)
	}
	httputils.WriteResp(w, resp)
}

// ListConsents handles ListConsents HTTP requests.
func (h *ConsentsHandler) ListConsents(w http.ResponseWriter, r *http.Request) {
	req := &cpb.ListConsentsRequest{Parent: r.RequestURI}
	resp, err := h.s.ListConsents(r.Context(), req)
	if err != nil {
		httputils.WriteError(w, err)
	}
	httputils.WriteResp(w, resp)
}

// StubConsents is a stub implementation.
type StubConsents struct {
	Consent *cpb.Consent
}

// DeleteConsent revokes a consent.
func (s *StubConsents) DeleteConsent(_ context.Context, req *cpb.DeleteConsentRequest) (*epb.Empty, error) {
	glog.Infof("DeleteConsent %v", req)
	return &epb.Empty{}, nil
}

// ListConsents lists the consents.
func (s *StubConsents) ListConsents(_ context.Context, req *cpb.ListConsentsRequest) (*cpb.ListConsentsResponse, error) {
	glog.Infof("ListConsents %v", req)
	return &cpb.ListConsentsResponse{Consents: []*cpb.Consent{s.Consent}}, nil
}

// FakeConsent is a fake consent.
// TODO: move these fakes to test file once implemented.
var FakeConsent = &cpb.Consent{
	Name:       "consents/fake-consent",
	User:       "fake-user",
	Client:     "fake-client",
	Items:      []string{"fake-visa-1", "fake-visa-2", "fake-visa-3"},
	Scopes:     []string{"fake-scope-1", "fake-scope-2"},
	Resouces:   []string{"fake-resource-1", "fake-resource-2"},
	CreateTime: ptypes.TimestampNow(),
	UpdateTime: ptypes.TimestampNow(),
}
