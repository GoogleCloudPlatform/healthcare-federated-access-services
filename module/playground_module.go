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

package module

import (
	"bytes"
	"fmt"
	"io"
	"net/http"

	"github.com/golang/protobuf/jsonpb"

	dampb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1"
)

// Playground enables test environment persona features.
// WARNING: do not use this in production systems as it bypasses security
// and allows anyone to log in as an administrator.
type Playground struct {
	damURL          string
	damClientID     string
	damClientSecret string
}

// NewPlaygroundModule creates a Playground module.
func NewPlaygroundModule(damURL, damClientID, damClientSecret string) Module {
	return &Playground{
		damURL:          damURL,
		damClientID:     damClientID,
		damClientSecret: damClientSecret,
	}
}

// ModuleName returns a named identifier for this module.
func (m *Playground) ModuleName() string {
	return "playground"
}

// LoadPersonas allows and IC to load personas from a DAM.
func (m *Playground) LoadPersonas(realm string) (map[string]*dampb.TestPersona, error) {
	if len(m.damURL) == 0 {
		return make(map[string]*dampb.TestPersona), nil
	}

	path := fmt.Sprintf("/dam/v1alpha/%s/testPersonas", realm)
	url := fmt.Sprintf("%s%s?client_id=%s&client_secret=%s", m.damURL, path, m.damClientID, m.damClientSecret)

	get, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	buf := new(bytes.Buffer)
	buf.ReadFrom(get.Body)
	body := buf.String()
	if get.StatusCode < 200 || get.StatusCode > 299 {
		return nil, fmt.Errorf("DAM test personas not available (status %d): %v", get.StatusCode, body)
	}
	out := dampb.GetTestPersonasResponse{}
	if err := jsonpb.UnmarshalString(body, &out); err != nil && err != io.EOF {
		return nil, fmt.Errorf("invalid DAM test personas: %v, got: %v", err, body)
	}

	return out.Personas, nil
}
