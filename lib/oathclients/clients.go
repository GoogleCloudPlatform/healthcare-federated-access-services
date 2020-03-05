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

// Package oathclients contains clients endpoints and helpers related to client credentials.
package oathclients

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"github.com/google/go-cmp/cmp" /* copybara-comment */
	"github.com/google/go-cmp/cmp/cmpopts" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"google.golang.org/protobuf/testing/protocmp" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/strutil" /* copybara-comment: strutil */

	glog "github.com/golang/glog" /* copybara-comment */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	cfgClients  = "clients"
	clientIDLen = 36
)

// CheckClientIntegrity check if the given clientHandler integrity.
func CheckClientIntegrity(name string, c *pb.Client) error {
	if err := httputils.CheckName("name", name, nil); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name), fmt.Sprintf("invalid clientHandler name %q: %v", name, err)).Err()
	}

	if uid := uuid.Parse(c.ClientId); uid == nil || len(c.ClientId) != clientIDLen {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, "clientId"), fmt.Sprintf("missing clientHandler ID or invalid format: %q", c.ClientId)).Err()
	}

	if path, err := check.CheckUI(c.Ui, true); err != nil {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, path), fmt.Sprintf("clientHandler UI settings: %v", err)).Err()
	}

	if len(c.RedirectUris) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, "RedirectUris"), "missing RedirectUris").Err()
	}

	for _, uri := range c.RedirectUris {
		if strings.HasPrefix(uri, "/") {
			continue
		}

		if !strutil.IsURL(uri) {
			return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, "RedirectUris"), fmt.Sprintf("RedirectUris %q is not url", uri)).Err()
		}
	}

	if len(c.Scope) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, "Scope"), "missing Scope").Err()
	}

	if len(c.GrantTypes) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, "GrantTypes"), "missing GrantTypes").Err()
	}

	if len(c.ResponseTypes) == 0 {
		return httputils.NewInfoStatus(codes.InvalidArgument, httputils.StatusPath(cfgClients, name, "ResponseTypes"), "missing ResponseTypes").Err()
	}

	return nil
}

// ExtractClientID from request.
func ExtractClientID(r *http.Request) string {
	cid := httputils.QueryParam(r, "client_id")
	if len(cid) > 0 {
		return cid
	}
	return httputils.QueryParam(r, "clientId")
}

// ExtractClientSecret from request.
func ExtractClientSecret(r *http.Request) string {
	cs := httputils.QueryParam(r, "client_secret")
	if len(cs) > 0 {
		return cs
	}
	return httputils.QueryParam(r, "clientSecret")
}

// SyncClients resets clients in hydra with given clients and secrets.
func SyncClients(httpClient *http.Client, hydraAdminURL string, clients map[string]*pb.Client, secrets map[string]string) (*pb.ClientState, error) {
	state, err := SyncState(httpClient, hydraAdminURL, clients, secrets)
	if err != nil {
		return nil, err
	}
	for name, client := range state.Add {
		sec := secrets[client.ClientId]
		thc := toHydraClient(client, name, sec, strfmt.NewDateTime())
		if _, err := hydra.CreateClient(httpClient, hydraAdminURL, thc); err != nil {
			return nil, err
		}
	}
	for name, client := range state.Update {
		sec := secrets[client.ClientId]
		thc := toHydraClient(client, name, sec, strfmt.NewDateTime())
		if _, err := hydra.UpdateClient(httpClient, hydraAdminURL, thc.ClientID, thc); err != nil {
			return nil, err
		}
	}
	for _, client := range state.Remove {
		if err := hydra.DeleteClient(httpClient, hydraAdminURL, client.ClientId); err != nil {
			return nil, err
		}
	}
	msg := fmt.Sprintf("sync hydra clients: added %d, updated %d, removed %d, unchanged %d, no_secret %d", len(state.Add), len(state.Update), len(state.Remove), len(state.Unchanged), len(state.NoSecret))
	state.Status = httputils.NewStatus(codes.OK, msg).Proto()
	glog.Infof(msg)
	return state, nil
}

// SyncState calculates what client sync operations are needed between hydra and the service.
func SyncState(httpClient *http.Client, hydraAdminURL string, clients map[string]*pb.Client, secrets map[string]string) (*pb.ClientState, error) {
	state := &pb.ClientState{
		Add:            make(map[string]*pb.Client),
		Update:         make(map[string]*pb.Client),
		UpdateDiff:     make(map[string]string),
		Remove:         make(map[string]*pb.Client),
		Unchanged:      make(map[string]*pb.Client),
		NoSecret:       make(map[string]*pb.Client),
		SecretMismatch: []string{},
	}
	cs, err := hydra.ListClients(httpClient, hydraAdminURL)
	if err != nil {
		return nil, err
	}

	// Populate existing Hydra clients by ClientID. As the logic handles
	// these clients, remove them from this map. Remaining items no longer
	// exist in the Federated Access component, so delete the from Hydra.
	removable := make(map[string]*hydraapi.Client)
	for _, c := range cs {
		removable[c.ClientID] = c
	}

	// Add clients to hydra.
	for n, cli := range clients {
		c := &pb.Client{}
		proto.Merge(c, cli)
		c.Ui = nil

		sec, ok := secrets[c.ClientId]
		if !ok {
			glog.Errorf("sync hydra clients: client %q has no secret, and will not be included in Hydra client list.", n)
			state.NoSecret[n] = c
			continue
		}

		hc, ok := removable[c.ClientId]
		if !ok {
			// Does not exist in hydra, so create.
			state.Add[n] = c
			continue
		}

		// Update an existing client if it has changed.
		fhc, hsec := fromHydraClient(hc)
		if cmp.Equal(fhc, c, protocmp.Transform(), cmpopts.EquateEmpty()) && hsec == sec {
			state.Unchanged[n] = c
		} else {
			state.Update[n] = c
			if sec != hsec {
				// Add the name of the client only, do not reveal the secrets in the state.
				state.SecretMismatch = append(state.SecretMismatch, n)
			}
			// Take the diff again without revealing the secrets.
			state.UpdateDiff[n] = cmp.Diff(fhc, c, protocmp.Transform(), cmpopts.EquateEmpty())
		}
		// Whether updated or unchanged above, remove it from the `removable` list to avoid removing the hydra client below.
		delete(removable, hc.ClientID)
	}

	// Remove remaining existing hydra clients on the `removable` list.
	for _, hc := range removable {
		c, _ := fromHydraClient(hc)
		state.Remove[hc.Name] = c
	}

	sort.Strings(state.SecretMismatch)
	msg := fmt.Sprintf("hydra clients status: add %d, update %d, remove %d, unchanged %d, no_secret %d", len(state.Add), len(state.Update), len(state.Remove), len(state.Unchanged), len(state.NoSecret))
	state.Status = httputils.NewStatus(codes.OK, msg).Proto()
	return state, nil
}
