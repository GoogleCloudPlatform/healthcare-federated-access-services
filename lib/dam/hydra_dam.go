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
	"context"
	"net/http"
	"net/url"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"golang.org/x/oauth2" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
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

	redirect, err := s.hydraLogin(r.Context(), challenge, login)
	if err != nil {
		hydra.SendLoginReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteRedirect(w, r, redirect)
	}
}

// hydraLogin returns redirect and status error
func (s *Service) hydraLogin(ctx context.Context, challenge string, login *hydraapi.LoginRequest) (string, error) {
	u, err := url.Parse(login.RequestURL)
	if err != nil {
		return "", errutil.WithErrorReason("url_parse", status.Errorf(codes.FailedPrecondition, "url parse: %v", err))
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
			return "", errutil.WithErrorReason("ttl_invalid", status.Errorf(codes.InvalidArgument, "ttl invalid: %v", err))
		}

		list := u.Query()["resource"]
		in.resources, err = s.resourceViewRoleFromRequest(list)
		if err != nil {
			return "", errutil.WithErrorReason("resource_invalid", status.Errorf(codes.InvalidArgument, "resource invalid: %v", err))
		}

		in.responseKeyFile = u.Query().Get("response_type") == "key-file-type"
	}

	out, err := s.auth(ctx, in)
	if err != nil {
		return "", err
	}

	var opts []oauth2.AuthCodeOption
	loginHint := u.Query().Get("login_hint")
	if len(loginHint) != 0 {
		opt := oauth2.SetAuthURLParam("login_hint", loginHint)
		opts = append(opts, opt)
	}

	auth := out.oauth.AuthCodeURL(out.stateID, opts...)

	return auth, nil
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
