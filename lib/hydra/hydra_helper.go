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

package hydra

import (
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */

	glog "github.com/golang/glog" /* copybara-comment */
)

const (
	// StateIDKey uses to store stateID in hydra context.
	StateIDKey = "state"
)

// ExtractLoginChallenge extracts login_challenge from request.
func ExtractLoginChallenge(r *http.Request) (string, *status.Status) {
	n := httputil.QueryParam(r, "login_challenge")
	if len(n) > 0 {
		return n, nil
	}
	return "", httputil.NewInfoStatus(codes.InvalidArgument, "", "request must include query 'login challenge'")
}

// ExtractConsentChallenge extracts consent_challenge from request.
func ExtractConsentChallenge(r *http.Request) (string, *status.Status) {
	n := httputil.QueryParam(r, "consent_challenge")
	if len(n) > 0 {
		return n, nil
	}
	return "", httputil.NewInfoStatus(codes.InvalidArgument, "", "request must include query 'consent_challenge'")
}

// ExtractStateIDInConsent extracts stateID in ConsentRequest Context.
func ExtractStateIDInConsent(consent *hydraapi.ConsentRequest) (string, *status.Status) {
	st, ok := consent.Context[StateIDKey]
	if !ok {
		return "", httputil.NewInfoStatus(codes.Internal, "", fmt.Sprintf("consent.Context[%s] not found", StateIDKey))
	}

	stateID, ok := st.(string)
	if !ok {
		return "", httputil.NewInfoStatus(codes.Internal, "", fmt.Sprintf("consent.Context[%s] in wrong type", StateIDKey))
	}

	return stateID, nil
}

// ExtractIdentitiesInConsent extracts identities in ConsentRequest Context.
func ExtractIdentitiesInConsent(consent *hydraapi.ConsentRequest) ([]string, *status.Status) {
	v, ok := consent.Context["identities"]
	if !ok {
		return nil, nil
	}

	var identities []string

	l, ok := v.([]interface{})
	if !ok {
		return nil, httputil.NewInfoStatus(codes.Internal, "", "consent.Context[identities] in wrong type")
	}

	for i, it := range l {
		id, ok := it.(string)
		if !ok {
			return nil, httputil.NewInfoStatus(codes.Internal, "", fmt.Sprintf("consent.Context[identities][%d] in wrong type", i))
		}

		identities = append(identities, id)
	}

	return identities, nil
}

// LoginSkip if hydra was already able to authenticate the user, skip will be true and we do not need to re-authenticate the user.
func LoginSkip(w http.ResponseWriter, r *http.Request, client *http.Client, login *hydraapi.LoginRequest, hydraAdminURL, challenge string) bool {
	if !login.Skip {
		return false
	}

	// You can apply logic here, for example update the number of times the user logged in.

	// TODO: provide metrics / audit logs for this case

	// Now it's time to grant the login request. You could also deny the request if something went terribly wrong
	resp, err := AcceptLogin(client, hydraAdminURL, challenge, &hydraapi.HandledLoginRequest{Subject: &login.Subject})
	if err != nil {
		httputil.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return true
	}

	httputil.WriteRedirect(w, r, resp.RedirectTo)
	return true
}

// ConsentSkip if hydra was already able to consent the user, skip will be true and we do not need to re-consent the user.
// Returns whether a consent is required and redirect address for the conset page.
func ConsentSkip(r *http.Request, client *http.Client, consent *hydraapi.ConsentRequest, hydraAdminURL, challenge string) (bool, string, error) {
	if !consent.Skip {
		return false, "", nil
	}

	// You can apply logic here, for example update the number of times the user consent.

	// TODO: provide metrics / audit logs for this case

	// Now it's time to grant the consent request. You could also deny the request if something went terribly wrong
	consentReq := &hydraapi.HandledConsentRequest{
		GrantedAudience: append(consent.RequestedAudience, consent.Client.ClientID),
		GrantedScope:    consent.RequestedScope,
		// TODO: need double check token has correct info.
	}
	resp, err := AcceptConsent(client, hydraAdminURL, challenge, consentReq)
	if err != nil {
		return false, "", err
	}

	return true, resp.RedirectTo, nil
}

// SendLoginSuccess sends login success to hydra.
func SendLoginSuccess(w http.ResponseWriter, r *http.Request, client *http.Client, hydraAdminURL, challenge, subject, stateID string, extra map[string]interface{}) {
	addr, err := LoginSuccess(r, client, hydraAdminURL, challenge, subject, stateID, extra)
	if err != nil {
		httputil.WriteError(w, err)
	}
	httputil.WriteRedirect(w, r, addr)
}

// LoginSuccess is the redirect for successful login.
func LoginSuccess(r *http.Request, client *http.Client, hydraAdminURL, challenge, subject, stateID string, extra map[string]interface{}) (string, error) {
	req := &hydraapi.HandledLoginRequest{
		Subject: &subject,
		Context: map[string]interface{}{},
	}

	if len(stateID) > 0 {
		req.Context[StateIDKey] = stateID
	}

	for k, v := range extra {
		req.Context[k] = v
	}

	resp, err := AcceptLogin(client, hydraAdminURL, challenge, req)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "%v", err)
	}
	return resp.RedirectTo, nil
}

// NormalizeIdentity converts hydra special format in access token to ga4gh.Identity
// 1. move "scp" to "scope"
// 2. move "extra.identities" to "identities"
func NormalizeIdentity(id *ga4gh.Identity) *ga4gh.Identity {
	if len(id.Scope) == 0 && len(id.Scp) > 0 {
		id.Scope = strings.Join(id.Scp, " ")
	}

	// move "identities" claim in "ext" claim to top level identities claim.
	l, ok := id.Extra["identities"]
	if !ok {
		return id
	}

	list, ok := l.([]interface{})
	if !ok {
		glog.Warning("id.Extra[identities] in wrong type")
		return id
	}

	if id.Identities == nil {
		id.Identities = map[string][]string{}
	}

	for i, it := range list {
		identity, ok := it.(string)
		if !ok {
			glog.Warningf("id.Extra[identities][%d] in wrong type", i)
			continue
		}

		id.Identities[identity] = nil
	}

	return id
}
