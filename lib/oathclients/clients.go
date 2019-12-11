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

	"google.golang.org/grpc/codes" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

const (
	cfgClients  = "clients"
	clientIDLen = 36
)

// CheckClientIntegrity check if the given clientHandler integrity.
func CheckClientIntegrity(name string, c *pb.Client) error {
	if err := common.CheckName("name", name, nil); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name), fmt.Sprintf("invalid clientHandler name %q: %v", name, err)).Err()
	}

	if _, err := common.ParseGUID(c.ClientId); err != nil || len(c.ClientId) != clientIDLen {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, "clientId"), fmt.Sprintf("missing clientHandler ID or invalid format: %q", c.ClientId)).Err()
	}

	if path, err := common.CheckUI(c.Ui, true); err != nil {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, path), fmt.Sprintf("clientHandler UI settings: %v", err)).Err()
	}

	if len(c.RedirectUris) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, "RedirectUris"), "missing RedirectUris").Err()
	}

	for _, uri := range c.RedirectUris {
		if strings.HasPrefix(uri, "/") {
			continue
		}

		if !common.IsURL(uri) {
			return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, "RedirectUris"), fmt.Sprintf("RedirectUris %q is not url", uri)).Err()
		}
	}

	if len(c.Scope) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, "Scope"), "missing Scope").Err()
	}

	if len(c.GrantTypes) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, "GrantTypes"), "missing GrantTypes").Err()
	}

	if len(c.ResponseTypes) == 0 {
		return common.NewInfoStatus(codes.InvalidArgument, common.StatusPath(cfgClients, name, "ResponseTypes"), "missing ResponseTypes").Err()
	}

	return nil
}

// ExtractClientID from request.
func ExtractClientID(r *http.Request) string {
	cid := common.GetParam(r, "client_id")
	if len(cid) > 0 {
		return cid
	}
	return common.GetParam(r, "clientId")
}

// ExtractClientSecret from request.
func ExtractClientSecret(r *http.Request) string {
	cs := common.GetParam(r, "client_secret")
	if len(cs) > 0 {
		return cs
	}
	return common.GetParam(r, "clientSecret")
}
