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
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/codes" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	cfgClients  = "clients"
	clientIDLen = 36
)

// CheckClientIntegrity check if the given clientHandler integrity.
func CheckClientIntegrity(name string, c *pb.Client) error {
	if err := httputil.CheckName("name", name, nil); err != nil {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name), fmt.Sprintf("invalid clientHandler name %q: %v", name, err)).Err()
	}

	if _, err := common.ParseGUID(c.ClientId); err != nil || len(c.ClientId) != clientIDLen {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, "clientId"), fmt.Sprintf("missing clientHandler ID or invalid format: %q", c.ClientId)).Err()
	}

	if path, err := httputil.CheckUI(c.Ui, true); err != nil {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, path), fmt.Sprintf("clientHandler UI settings: %v", err)).Err()
	}

	if len(c.RedirectUris) == 0 {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, "RedirectUris"), "missing RedirectUris").Err()
	}

	for _, uri := range c.RedirectUris {
		if strings.HasPrefix(uri, "/") {
			continue
		}

		if !common.IsURL(uri) {
			return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, "RedirectUris"), fmt.Sprintf("RedirectUris %q is not url", uri)).Err()
		}
	}

	if len(c.Scope) == 0 {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, "Scope"), "missing Scope").Err()
	}

	if len(c.GrantTypes) == 0 {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, "GrantTypes"), "missing GrantTypes").Err()
	}

	if len(c.ResponseTypes) == 0 {
		return httputil.NewInfoStatus(codes.InvalidArgument, httputil.StatusPath(cfgClients, name, "ResponseTypes"), "missing ResponseTypes").Err()
	}

	return nil
}

// ExtractClientID from request.
func ExtractClientID(r *http.Request) string {
	cid := httputil.GetParam(r, "client_id")
	if len(cid) > 0 {
		return cid
	}
	return httputil.GetParam(r, "clientId")
}

// ExtractClientSecret from request.
func ExtractClientSecret(r *http.Request) string {
	cs := httputil.GetParam(r, "client_secret")
	if len(cs) > 0 {
		return cs
	}
	return httputil.GetParam(r, "clientSecret")
}

// ResetClients resets clients in hydra with given clients and secrets.
func ResetClients(httpClient *http.Client, hydraAdminURL string, clients map[string]*pb.Client, secrets map[string]string) error {
	var added, updated, removed, skipped int
	cs, err := hydra.ListClients(httpClient, hydraAdminURL)
	if err != nil {
		return err
	}

	// Populate existing Hydra clients by ClientID. As the logic handles
	// these clients, remove them from this map. Remaining items no longer
	// exist in the Federated Access component, so delete the from Hydra.
	existing := make(map[string]*hydraapi.Client)
	for _, c := range cs {
		existing[c.ClientID] = c
	}

	// Add clients to hydra.
	for n, cli := range clients {
		c := &pb.Client{}
		proto.Merge(c, cli)
		c.Ui = nil

		sec, ok := secrets[c.ClientId]
		if !ok {
			glog.Errorf("Client %s has no secret, and will not be included in Hydra client list.", n)
			skipped++
			continue
		}

		hc, ok := existing[c.ClientId]
		if !ok {
			// Does not exist, so create.
			thc := toHydraClient(c, n, sec, strfmt.NewDateTime())
			if _, err := hydra.CreateClient(httpClient, hydraAdminURL, thc); err != nil {
				return err
			}
			added++
			continue
		}

		// Update an existing client.
		thc := toHydraClient(c, n, sec, hc.CreatedAt)
		if _, err := hydra.UpdateClient(httpClient, hydraAdminURL, thc.ClientID, thc); err != nil {
			return err
		}
		delete(existing, thc.ClientID)
		updated++
	}

	// Remove remaining existing hydra clients.
	for _, hc := range existing {
		if err := hydra.DeleteClient(httpClient, hydraAdminURL, hc.ClientID); err != nil {
			return err
		}
		removed++
	}

	glog.Infof("reset hydra clients: added %d, updated %d, removed %d, skipped %d, total %d", added, updated, removed, skipped, len(clients))
	return nil
}
