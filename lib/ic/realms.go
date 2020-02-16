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

package ic

import (
	"net/http"

	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh" /* copybara-comment: ga4gh */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/handlerfactory" /* copybara-comment: handlerfactory */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

func (s *Service) realmFactory() *handlerfactory.HandlerFactory {
	return &handlerfactory.HandlerFactory{
		TypeName:            "realm",
		NameField:           "realm",
		PathPrefix:          realmPath,
		HasNamedIdentifiers: true,
		NewHandler: func(w http.ResponseWriter, r *http.Request) handlerfactory.HandlerInterface {
			return &realm{
				s:     s,
				w:     w,
				r:     r,
				input: &pb.RealmRequest{},
			}
		},
	}
}

type realm struct {
	s     *Service
	w     http.ResponseWriter
	r     *http.Request
	input *pb.RealmRequest
	item  *pb.Realm
	cfg   *pb.IcConfig
	id    *ga4gh.Identity
}

func (c *realm) Setup(tx storage.Tx) (int, error) {
	cfg, _, id, status, err := c.s.handlerSetup(tx, c.r, noScope, c.input)
	c.cfg = cfg
	c.id = id
	return status, err
}

func (c *realm) LookupItem(name string, vars map[string]string) bool {
	// Accept any name that passes the name check.
	c.item = &pb.Realm{}
	return true
}

func (c *realm) NormalizeInput(name string, vars map[string]string) error {
	if err := httputil.DecodeProtoReq(c.input, c.r); err != nil {
		return err
	}
	if c.input == nil {
		c.input = &pb.RealmRequest{}
	}
	if c.input.Item == nil {
		c.input.Item = &pb.Realm{}
	}
	return nil
}

func (c *realm) Get(name string) error {
	if c.item != nil {
		httputil.WriteProtoResp(c.w, c.item)
	}
	return nil
}

func (c *realm) Post(name string) error {
	// Accept, but do nothing.
	return nil
}

func (c *realm) Put(name string) error {
	// Accept, but do nothing.
	return nil
}

func (c *realm) Patch(name string) error {
	// Accept, but do nothing.
	return nil
}

func (c *realm) Remove(name string) error {
	if err := c.s.store.Wipe(name); err != nil {
		return err
	}
	if name == storage.DefaultRealm {
		return c.s.ImportFiles(importDefault)
	}
	return nil
}

func (c *realm) CheckIntegrity() *status.Status {
	return nil
}

func (c *realm) Save(tx storage.Tx, name string, vars map[string]string, desc, typeName string) error {
	// Accept, but do nothing.
	return nil
}
