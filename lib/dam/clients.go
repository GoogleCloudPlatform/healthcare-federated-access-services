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
	"net/http"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/check" /* copybara-comment: check */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	cpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
)

type clientService struct {
	s    *Service
	cfg  *pb.DamConfig
	sec  *pb.DamSecrets
	item *cpb.Client
	save bool
}

func (c *clientService) ClientByName(name string) *cpb.Client {
	return c.cfg.Clients[name]
}

func (c *clientService) HandlerSetup(tx storage.Tx, r *http.Request) (*ga4gh.Identity, int, error) {
	cfg, id, status, err := c.s.handlerSetup(tx, r, noScope, nil)
	if err != nil {
		return id, status, err
	}
	sec, err := c.s.loadSecrets(tx)

	c.cfg = cfg
	c.sec = sec
	return id, status, err
}

func (c *clientService) SaveClient(name, secret string, cli *cpb.Client) {
	c.cfg.Clients[name] = cli
	c.sec.ClientSecrets[cli.ClientId] = secret
	c.save = true
}

func (c *clientService) RemoveClient(name string, cli *cpb.Client) {
	delete(c.cfg.Clients, name)
	delete(c.sec.ClientSecrets, cli.ClientId)
	c.save = true
}

func (c *clientService) Save(tx storage.Tx, desc, typeName string, r *http.Request, id *ga4gh.Identity, m *cpb.ConfigModification) error {
	if !c.save || (m != nil && m.DryRun) {
		return nil
	}

	if err := c.s.saveConfig(c.cfg, desc, typeName, r, id, c.item, c.item, toDAMModification(m), tx); err != nil {
		return err
	}
	if err := c.s.saveSecrets(c.sec, desc, typeName, r, id, tx); err != nil {
		return err
	}

	return nil
}

func (c *clientService) CheckIntegrity(r *http.Request, m *cpb.ConfigModification) *status.Status {
	if err := check.CheckReadOnly(getRealm(r), c.cfg.Options.ReadOnlyMasterRealm, c.cfg.Options.WhitelistedRealms); err != nil {
		return httputil.NewStatus(codes.InvalidArgument, err.Error())
	}
	if err := configRevision(toDAMModification(m), c.cfg); err != nil {
		return httputil.NewStatus(codes.InvalidArgument, err.Error())
	}
	if st := c.s.CheckIntegrity(c.cfg); st != nil {
		return st
	}
	return nil
}

//////////////////////////////////////////////////////////////////
// GET /dam/v1alpha/{realm}/clients/{name}:
//   Return self client information
//////////////////////////////////////////////////////////////////

func (s *Service) clientFactory() *handlerfactory.HandlerFactory {
	c := &clientService{s: s}

	return &handlerfactory.HandlerFactory{
		TypeName:            "client",
		PathPrefix:          clientPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return oathclients.NewClientHandler(w, r, c)
		},
	}
}

//////////////////////////////////////////////////////////////////
// GET /dam/v1alpha/{realm}/config/clients/{name}:
//   Return any given client information
//   Require admin token
//
// POST /dam/v1alpha/{realm}/config/clients/{name}:
//   Add given client in http body
//   Require admin token
//   Return added client information
//
// PATCH /dam/v1alpha/{realm}/config/clients/{name}:
//   Update given client
//   Require admin token
//   Return any client information
//
// DELETE /dam/v1alpha/{realm}/config/clients/{name}:
//   Delete given client
//   Require admin token
//   Return nothing
//////////////////////////////////////////////////////////////////

func (s *Service) configClientFactory() *handlerfactory.HandlerFactory {
	c := &clientService{s: s}

	return &handlerfactory.HandlerFactory{
		TypeName:            "configClient",
		PathPrefix:          configClientPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return oathclients.NewAdminClientHandler(w, r, c, c.s.useHydra, c.s.httpClient, c.s.hydraAdminURL)
		},
	}
}

func toDAMPersonaModification(p *cpb.ConfigModification_PersonaModification) *pb.ConfigModification_PersonaModification {
	if p == nil {
		return nil
	}
	return &pb.ConfigModification_PersonaModification{
		Access:       p.Access,
		AddAccess:    p.AddAccess,
		RemoveAccess: p.RemoveAccess,
	}
}

func toDAMModification(m *cpb.ConfigModification) *pb.ConfigModification {
	if m == nil {
		return nil
	}
	res := &pb.ConfigModification{
		Revision:     m.Revision,
		TestPersonas: map[string]*pb.ConfigModification_PersonaModification{},
		DryRun:       m.DryRun,
	}

	for k, v := range m.TestPersonas {
		res.TestPersonas[k] = toDAMPersonaModification(v)
	}

	return res
}
