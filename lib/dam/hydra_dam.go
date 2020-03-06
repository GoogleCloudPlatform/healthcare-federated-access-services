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

package dam

import (
	"bytes"
	"io/ioutil"
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

const (
	stateIDInHydra = "state"
)

// HydraLogin handles login request from hydra.
func (s *Service) HydraLogin(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use login_challenge fetch information from hydra.
	challenge, sts := hydra.ExtractLoginChallenge(r)
	if sts != nil {
		httputils.WriteError(w, sts.Err())
		return
	}

	login, err := hydra.GetLoginRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	if hydra.LoginSkip(w, r, s.httpClient, login, s.hydraAdminURL, challenge) {
		return
	}

	u, err := url.Parse(login.RequestURL)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	in := authHandlerIn{
		challenge: challenge,
	}

	// Request tokens for call DAM endpoints, if scope includes "identities".
	if stringset.Contains(login.RequestedScope, "identities") {
		in.tokenType = pb.ResourceTokenRequestState_ENDPOINT
		in.realm = u.Query().Get("realm")
		if len(in.realm) == 0 {
			in.realm = storage.DefaultRealm
		}
	} else {
		in.tokenType = pb.ResourceTokenRequestState_DATASET
		in.ttl, err = extractTTL(u.Query().Get("max_age"), u.Query().Get("ttl"))
		if err != nil {
			httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "%v", err))
			return
		}

		list := u.Query()["resource"]
		in.resources, err = s.resourceViewRoleFromRequest(list)
		if err != nil {
			httputils.WriteError(w, status.Errorf(codes.InvalidArgument, "%v", err))
			return
		}

		in.responseKeyFile = u.Query().Get("response_type") == "key-file-type"
	}

	out, st, err := s.auth(r.Context(), in)
	if err != nil {
		httputils.WriteError(w, status.Errorf(httputils.RPCCode(st), "%v", err))
		return
	}

	var opts []oauth2.AuthCodeOption
	loginHint := u.Query().Get("login_hint")
	if len(loginHint) != 0 {
		opt := oauth2.SetAuthURLParam("login_hint", loginHint)
		opts = append(opts, opt)
	}

	auth := out.oauth.AuthCodeURL(out.stateID, opts...)

	httputils.WriteRedirect(w, r, auth)
}

// HydraConsent handles consent request from hydra.
func (s *Service) HydraConsent(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	// Use consent_challenge fetch information from hydra.
	challenge, st := hydra.ExtractConsentChallenge(r)
	if st != nil {
		httputils.WriteError(w, st.Err())
		return
	}

	consent, err := hydra.GetConsentRequest(s.httpClient, s.hydraAdminURL, challenge)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	identities, sts := hydra.ExtractIdentitiesInConsent(consent)
	if sts != nil {
		httputils.WriteError(w, sts.Err())
		return
	}

	var stateID string
	if len(identities) == 0 {
		stateID, sts = hydra.ExtractStateIDInConsent(consent)
		if sts != nil {
			httputils.WriteError(w, sts.Err())
			return
		}
	}

	tokenID := uuid.New()

	req := &hydraapi.HandledConsentRequest{
		GrantedAudience: append(consent.RequestedAudience, consent.Client.ClientID),
		GrantedScope:    consent.RequestedScope,
		Session: &hydraapi.ConsentRequestSessionData{
			AccessToken: map[string]interface{}{
				"tid": tokenID,
			},
			IDToken: map[string]interface{}{
				"tid": tokenID,
			},
		},
	}

	if len(stateID) > 0 {
		req.Session.AccessToken["cart"] = stateID
	} else if len(identities) > 0 {
		req.Session.AccessToken["identities"] = identities
	}

	resp, err := hydra.AcceptConsent(s.httpClient, s.hydraAdminURL, challenge, req)
	if err != nil {
		httputils.WriteError(w, status.Errorf(codes.Unavailable, "%v", err))
		return
	}

	httputils.WriteRedirect(w, r, resp.RedirectTo)
}

func (s *Service) extractCartFromAccessToken(token string) (string, error) {
	claims, err := hydra.Introspect(s.httpClient, s.hydraAdminURL, token)
	if err != nil {
		return "", err
	}

	v, ok := claims.Extra["cart"]
	if !ok {
		return "", status.Errorf(codes.Unauthenticated, "token does not have 'cart' claim")
	}

	cart, ok := v.(string)
	if !ok {
		return "", status.Errorf(codes.Internal, "token 'cart' claim have unwanted type")
	}

	return cart, nil
}

// HydraOAuthToken proxy the POST /oauth2/token request.
// - for code exhange token: do nothing, just proxy.
// - for refresh token exchange token: check the token is not revoked before proxy the request.
func (s *Service) HydraOAuthToken(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	// introspect the refresh token before proxy the request to exchange.

	// Encode form back into request body
	r.Body = ioutil.NopCloser(bytes.NewBufferString(r.PostForm.Encode()))

	s.HydraPublicURLProxy.ServeHTTP(w, r)
}
