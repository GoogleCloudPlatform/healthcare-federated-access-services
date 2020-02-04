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

package oathclients

import (
	"fmt"
	"net/http"

	"github.com/golang/protobuf/proto" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/go-openapi/strfmt" /* copybara-comment */
	"github.com/pborman/uuid" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/apis/hydraapi" /* copybara-comment: hydraapi */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/common" /* copybara-comment: common */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydra" /* copybara-comment: hydra */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

var (
	// TODO: double check the default values.
	defaultScope         = "openid offline ga4gh_passport_v1 profile email identities account_admin"
	defaultGrantTypes    = []string{"authorization_code"}
	defaultResponseTypes = []string{"token", "code", "id_token"}
)

// ClientService provides data storage for clients.
type ClientService interface {
	HandlerSetup(tx storage.Tx, isAdmin bool, r *http.Request) (*ga4gh.Identity, int, error)
	ClientByName(name string) *pb.Client
	SaveClient(name, secret string, cli *pb.Client)
	RemoveClient(name string, cli *pb.Client)
	Save(tx storage.Tx, desc, typeName string, r *http.Request, id *ga4gh.Identity, m *pb.ConfigModification) error
	CheckIntegrity(r *http.Request, m *pb.ConfigModification) *status.Status
}

//////////////////////////////////////////////////////////////////
// GET /identity/v1alpha/{realm}/clients/{name}
// GET /dam/v1alpha/{realm}/clients/{name}
//   Return self client information
//////////////////////////////////////////////////////////////////

type clientHandler struct {
	w        http.ResponseWriter
	r        *http.Request
	s        ClientService
	clientID string
	item     *pb.Client
	id       *ga4gh.Identity
}

// NewClientHandler returns clientHandler.
func NewClientHandler(w http.ResponseWriter, r *http.Request, s ClientService) common.HandlerInterface {
	return &clientHandler{w: w, r: r, s: s}
}

func (c *clientHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	clientID := ExtractClientID(c.r)
	if len(clientID) == 0 {
		return http.StatusBadRequest, fmt.Errorf("request requires clientID")
	}

	id, status, err := c.s.HandlerSetup(tx, isAdmin, c.r)
	c.id = id
	c.clientID = clientID

	return status, err
}

func (c *clientHandler) LookupItem(name string, vars map[string]string) bool {
	clientID := ExtractClientID(c.r)
	cli := c.s.ClientByName(name)
	if cli != nil && cli.ClientId == clientID {
		c.item = cli
		return true
	}
	return false
}

func (c *clientHandler) NormalizeInput(name string, vars map[string]string) error {
	return nil
}

func (c *clientHandler) Get(name string) error {
	return common.SendResponse(&pb.ClientResponse{
		Client: c.item,
	}, c.w)
}

func (c *clientHandler) Post(name string) error {
	return fmt.Errorf("POST not allowed")
}

func (c *clientHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

func (c *clientHandler) Patch(name string) error {
	return fmt.Errorf("PATCH not allowed")
}

func (c *clientHandler) Remove(name string) error {
	return fmt.Errorf("REMOVE not allowed")
}

func (c *clientHandler) CheckIntegrity() *status.Status {
	return nil
}

func (c *clientHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}

//////////////////////////////////////////////////////////////////
// GET /identity/v1alpha/{realm}/config/clients/{name}:
// GET /dam/v1alpha/{realm}/config/clients/{name}:
//   Return any given client information
//   Require admin token
//
// POST /identity/v1alpha/{realm}/config/clients/{name}:
// POST /dam/v1alpha/{realm}/config/clients/{name}:
//   Add given client in http body
//   Require admin token
//   Return added client information
//
// PATCH /identity/v1alpha/{realm}/config/clients/{name}:
// PATCH /dam/v1alpha/{realm}/config/clients/{name}:
//   Update given client
//   Require admin token
//   Return any client information
//
// DELETE /identity/v1alpha/{realm}/config/clients/{name}:
// DELETE /dam/v1alpha/{realm}/config/clients/{name}:
//   Delete given client
//   Require admin token
//   Return nothing
//////////////////////////////////////////////////////////////////

type adminClientHandler struct {
	w             http.ResponseWriter
	r             *http.Request
	s             ClientService
	useHydra      bool
	httpClient    *http.Client
	hydraAdminURL string
	input         *pb.ConfigClientRequest
	item          *pb.Client
	id            *ga4gh.Identity
	tx            storage.Tx
}

// NewAdminClientHandler returns adminClientHandler
func NewAdminClientHandler(w http.ResponseWriter, r *http.Request, s ClientService, useHydra bool, httpClient *http.Client, hydraAdminURL string) common.HandlerInterface {
	return &adminClientHandler{w: w, r: r, s: s, useHydra: useHydra, httpClient: httpClient, hydraAdminURL: hydraAdminURL}
}

func (c *adminClientHandler) Setup(tx storage.Tx, isAdmin bool) (int, error) {
	id, status, err := c.s.HandlerSetup(tx, isAdmin, c.r)
	c.id = id
	c.tx = tx
	return status, err
}

func (c *adminClientHandler) LookupItem(name string, vars map[string]string) bool {
	c.item = c.s.ClientByName(name)
	return c.item != nil
}

func (c *adminClientHandler) NormalizeInput(name string, vars map[string]string) error {
	c.input = &pb.ConfigClientRequest{}
	if err := common.GetRequest(c.input, c.r); err != nil {
		return err
	}
	if c.input.Item == nil {
		c.input.Item = &pb.Client{}
	}
	if c.input.Item.RedirectUris == nil {
		c.input.Item.RedirectUris = []string{}
	}
	if c.input.Item.Ui == nil {
		c.input.Item.Ui = make(map[string]string)
	}

	return nil
}

func (c *adminClientHandler) Get(name string) error {
	return common.SendResponse(&pb.ConfigClientResponse{Client: c.item}, c.w)
}

func (c *adminClientHandler) Post(name string) error {
	input := c.input.Item

	if len(input.ClientId) == 0 {
		input.ClientId = uuid.New()
	}
	if len(input.Scope) == 0 {
		input.Scope = defaultScope
	}
	if len(input.GrantTypes) == 0 {
		input.GrantTypes = defaultGrantTypes
	}
	if len(input.ResponseTypes) == 0 {
		input.ResponseTypes = defaultResponseTypes
	}

	if err := CheckClientIntegrity(name, input); err != nil {
		return err
	}

	out := proto.Clone(input).(*pb.Client)
	sec := uuid.New()

	// Create the client on hydra.
	if c.useHydra {
		hyCli := toHydraClient(c.input.Item, name, sec, strfmt.NewDateTime())
		resp, err := hydra.CreateClient(c.httpClient, c.hydraAdminURL, hyCli)
		if err != nil {
			return err
		}
		out, sec = fromHydraClient(resp)
		out.Ui = input.Ui
	}

	c.s.SaveClient(name, sec, out)

	// Return the created client.
	return common.SendResponse(&pb.ConfigClientResponse{
		Client:       out,
		ClientSecret: sec}, c.w)
}

func (c *adminClientHandler) Put(name string) error {
	return fmt.Errorf("PUT not allowed")
}

func (c *adminClientHandler) Patch(name string) error {
	// TODO should use field mask for update.

	input := c.input.Item
	if len(input.ClientId) == 0 {
		input.ClientId = c.item.ClientId
	}
	if input.ClientId != c.item.ClientId {
		return fmt.Errorf("invalid client_id")
	}
	if len(input.Scope) == 0 {
		input.Scope = c.item.Scope
	}
	if len(input.ResponseTypes) == 0 {
		input.ResponseTypes = c.item.ResponseTypes
	}
	if len(input.GrantTypes) == 0 {
		input.GrantTypes = c.item.GrantTypes
	}
	if len(input.RedirectUris) == 0 {
		input.RedirectUris = c.item.RedirectUris
	}
	if len(input.Ui) == 0 {
		input.Ui = c.item.Ui
	}

	if err := CheckClientIntegrity(name, input); err != nil {
		return err
	}

	out := proto.Clone(input).(*pb.Client)
	sec := uuid.New()

	if c.useHydra {
		hyCli := toHydraClient(input, name, sec, strfmt.NewDateTime())
		resp, err := hydra.UpdateClient(c.httpClient, c.hydraAdminURL, hyCli.ClientID, hyCli)
		if err != nil {
			return err
		}
		out, sec = fromHydraClient(resp)
		out.Ui = input.Ui
	}

	c.s.SaveClient(name, sec, out)

	// Return the updated client.
	return common.SendResponse(&pb.ConfigClientResponse{
		Client:       out,
		ClientSecret: sec}, c.w)
}

func (c *adminClientHandler) Remove(name string) error {
	if c.useHydra {
		err := hydra.DeleteClient(c.httpClient, c.hydraAdminURL, c.item.ClientId)
		if err != nil {
			return err
		}
	}

	c.s.RemoveClient(name, c.item)

	return nil
}

func (c *adminClientHandler) CheckIntegrity() *status.Status {
	return c.s.CheckIntegrity(c.r, extractConfigModification(c.input))
}

func (c *adminClientHandler) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	return c.s.Save(c.tx, desc, typeName, c.r, c.id, extractConfigModification(c.input))
}

func extractConfigModification(input *pb.ConfigClientRequest) *pb.ConfigModification {
	if input == nil {
		return nil
	}
	return input.Modification
}

func toHydraClient(c *pb.Client, name, secret string, createdAt strfmt.DateTime) *hydraapi.Client {
	return &hydraapi.Client{
		Name:          name,
		ClientID:      c.ClientId,
		Secret:        secret,
		Scope:         c.Scope,
		GrantTypes:    c.GrantTypes,
		ResponseTypes: c.ResponseTypes,
		RedirectURIs:  c.RedirectUris,
		CreatedAt:     createdAt,
	}
}

func fromHydraClient(c *hydraapi.Client) (*pb.Client, string) {
	return &pb.Client{
		ClientId:      c.ClientID,
		Scope:         c.Scope,
		GrantTypes:    c.GrantTypes,
		ResponseTypes: c.ResponseTypes,
		RedirectUris:  c.RedirectURIs,
	}, c.Secret
}
