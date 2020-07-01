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
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"bitbucket.org/creachadair/stringset" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

func (s *Service) hydraConsentRememberConsentOrInformationReleasePage(consent *hydraapi.ConsentRequest, stateID string, state *pb.ResourceTokenRequestState, tx storage.Tx) (*htmlPageOrRedirectURL, error) {
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
