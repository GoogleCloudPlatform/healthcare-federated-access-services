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

package dam

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/errutil" /* copybara-comment: errutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/timeutil" /* copybara-comment: timeutil */

	glog "github.com/golang/glog" /* copybara-comment */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	cspb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/store/consents" /* copybara-comment: go_proto */
)

const (
	rememberedConsentExpires = 90 * 24 * time.Hour
)

func (s *Service) hydraConsentRememberConsentOrInformationReleasePage(consent *hydraapi.ConsentRequest, stateID string, state *pb.ResourceTokenRequestState, tx storage.Tx) (*htmlPageOrRedirectURL, error) {

	rcp := &cspb.RememberedConsentPreference{}
	err := s.store.ReadTx(storage.RememberedConsentDatatype, storage.DefaultRealm, state.Subject, state.Subject, storage.LatestRev, rcp, tx)
	if err != nil && !storage.ErrNotFound(err) {
		return nil, status.Errorf(codes.Internal, "read remembered consent failed: %v", err)
	}

	found := err == nil

	if found && rcp.ExpireTime.Seconds < time.Now().Unix() {
		err := s.store.DeleteTx(storage.RememberedConsentDatatype, storage.DefaultRealm, state.Subject, state.Subject, storage.LatestRev, tx)
		if err != nil {
			return nil, status.Errorf(codes.Internal, "delete expired remembered consent failed: %v", err)
		}

		found = false
	}

	// has valid remembered consent
	if found && s.useHydra {
		return s.acceptHydraConsent(stateID, state, tx)
	}

	return s.informationReleasePage(consent, stateID, state)
}

func (s *Service) informationReleasePage(consent *hydraapi.ConsentRequest, stateID string, state *pb.ResourceTokenRequestState) (*htmlPageOrRedirectURL, error) {
	args := toInformationReleaseArgs(consent, stateID, state, s.consentDashboardURL)
	sb := &strings.Builder{}

	if err := s.infomationReleasePageTmpl.Execute(sb, args); err != nil {
		return nil, status.Errorf(codes.Internal, "generate information release page failed: %v", err)
	}

	return &htmlPageOrRedirectURL{page: sb.String()}, nil
}

func toInformationReleaseArgs(consent *hydraapi.ConsentRequest, stateID string, state *pb.ResourceTokenRequestState, consentDashboardURL string) *informationReleaseArgs {
	dashboardURL := strings.ReplaceAll(consentDashboardURL, "${USER_ID}", consent.Subject)

	args := &informationReleaseArgs{
		AssetDir:            assetPath,
		ApplicationName:     consent.Client.Name,
		State:               stateID,
		ID:                  consent.Subject,
		Offline:             stringset.Contains(state.RequestedScope, "offline"),
		IsDataset:           len(state.Resources) > 0,
		ConsentDashboardURL: dashboardURL,
	}

	if args.IsDataset {
		for _, ds := range state.Resources {
			n := fmt.Sprintf("%s/%s/%s/%s", ds.Resource, ds.View, ds.Role, ds.Interface)
			args.Information = append(args.Information, n)
		}
	} else {
		args.Information = state.Identities
	}

	return args
}

type informationReleaseArgs struct {
	AssetDir            string
	ApplicationName     string
	State               string
	ID                  string
	Offline             bool
	IsDataset           bool
	Information         []string
	ConsentDashboardURL string
}

// AcceptInformationRelease is the HTTP handler for "dam/inforelease/accept" endpoint.
func (s *Service) AcceptInformationRelease(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	challenge, redirect, err := s.acceptInformationRelease(r)
	if err == nil {
		httputils.WriteRedirect(w, r, redirect)
		return
	}

	if s.useHydra && len(challenge) > 0 {
		hydra.SendConsentReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// acceptInformationRelease returns challenge, redirect and status error
func (s *Service) acceptInformationRelease(r *http.Request) (_, _ string, ferr error) {
	stateID := httputils.QueryParam(r, "state")
	if len(stateID) == 0 {
		return "", "", status.Errorf(codes.InvalidArgument, "missing %q parameter", "state")
	}

	rememberOpt := httputils.QueryParam(r, "remember")
	remember := false
	switch rememberOpt {
	case "remember-release-any":
		remember = true
	case "remember-none":
		remember = false
	default:
		return "", "", status.Errorf(codes.InvalidArgument, "unknown remember option %q", rememberOpt)
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return "", "", status.Errorf(codes.Unavailable, "accept info release transaction creation failed: %v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "accept info release transaction finish failed: %v", err)
		}
	}()

	state := &pb.ResourceTokenRequestState{}
	err = s.store.ReadTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", "", status.Errorf(codes.Internal, "accept info release datastore read failed: %v", err)
	}

	challenge := state.ConsentChallenge

	// if the consent need to be remembered
	now := time.Now()
	if remember {
		rcp := &cspb.RememberedConsentPreference{
			ClientName:       state.ClientName,
			CreateTime:       timeutil.TimestampProto(now),
			ExpireTime:       timeutil.TimestampProto(now.Add(rememberedConsentExpires)),
			RequestMatchType: cspb.RememberedConsentPreference_ANYTHING,
			ReleaseType:      cspb.RememberedConsentPreference_ANYTHING_NEEDED,
		}

		err = s.store.WriteTx(storage.RememberedConsentDatatype, state.Realm, state.Subject, state.Subject, storage.LatestRev, rcp, nil, tx)
		if err != nil {
			return challenge, "", status.Errorf(codes.Internal, "accept info release datastore write remember consent failed: %v", err)
		}
	}

	htmlPageOrRedirect, err := s.acceptHydraConsent(stateID, state, tx)
	if err != nil {
		return challenge, "", err
	}

	return challenge, htmlPageOrRedirect.redirect, nil
}

// RejectInformationRelease is the HTTP handler for "dam/inforelease/reject" endpoint.
func (s *Service) RejectInformationRelease(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()

	challenge, err := s.rejectInformationRelease(r)

	if err == nil {
		glog.Errorln("rejectInformationRelease() should return err")
		err = status.Errorf(codes.Internal, "unknown err from rejectInformationRelease()")
	}

	if s.useHydra && len(challenge) > 0 {
		hydra.SendConsentReject(w, r, s.httpClient, s.hydraAdminURL, challenge, err)
	} else {
		httputils.WriteError(w, err)
	}
}

// rejectInformationRelease returns the challenge and error message.
func (s *Service) rejectInformationRelease(r *http.Request) (_ string, ferr error) {
	stateID := httputils.QueryParam(r, "state")
	if len(stateID) == 0 {
		return "", status.Errorf(codes.InvalidArgument, "missing %q parameter", "state")
	}

	tx, err := s.store.Tx(true)
	if err != nil {
		return "", status.Errorf(codes.Unavailable, "reject info release transaction creation failed: %v", err)
	}
	defer func() {
		err := tx.Finish()
		if ferr == nil && err != nil {
			ferr = status.Errorf(codes.Internal, "reject info release transaction finish failed: %v", err)
		}
	}()

	state := &pb.ResourceTokenRequestState{}
	err = s.store.ReadTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, state, tx)
	if err != nil {
		return "", status.Errorf(codes.Internal, "reject info release datastore read failed: %v", err)
	}

	challenge := state.ConsentChallenge

	// The temporary state for information releasing process can be only used once.
	err = s.store.DeleteTx(storage.ResourceTokenRequestStateDataType, storage.DefaultRealm, storage.DefaultUser, stateID, storage.LatestRev, tx)
	if err != nil {
		return challenge, status.Errorf(codes.Internal, "reject info release datastore delete failed: %v", err)
	}

	return challenge, errutil.WithErrorReason("user_denied", status.Errorf(codes.Unauthenticated, "User denied releasing consent"))
}
