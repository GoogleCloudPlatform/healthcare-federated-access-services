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
	"testing"

	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
)

func TestCheckClientIntegrity(t *testing.T) {
	clientID := "00000000-0000-0000-0000-000000000000"
	client := &pb.Client{
		ClientId:      clientID,
		Scope:         "scope",
		RedirectUris:  []string{"/", "https://example.com"},
		GrantTypes:    []string{"GrantTypes"},
		ResponseTypes: []string{"ResponseTypes"},
		Ui: map[string]string{
			"label":       "l",
			"description": "d",
		},
	}

	if err := CheckClientIntegrity("test_client", client); err != nil {
		t.Errorf("CheckClientIntegrity(test_client, %v) failed: %v", client, err)
	}
}

func TestCheckClientIntegrity_Error(t *testing.T) {
	clientID := "00000000-0000-0000-0000-000000000000"
	clientName := "test_client"
	client := &pb.Client{
		ClientId:      clientID,
		Scope:         "scope",
		RedirectUris:  []string{"/", "https://example.com"},
		GrantTypes:    []string{"GrantTypes"},
		ResponseTypes: []string{"ResponseTypes"},
		Ui: map[string]string{
			"label":       "l",
			"description": "d",
		},
	}

	tests := []struct {
		name       string
		clientName string
		client     *pb.Client
	}{
		{
			name:       "short client name",
			clientName: "1",
			client:     client,
		},
		{
			name:       "invalid client_id",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      "invalid",
				Scope:         "scope",
				RedirectUris:  []string{"/", "https://example.com"},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
		{
			name:       "missing client_id",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      "",
				Scope:         "scope",
				RedirectUris:  []string{"/", "https://example.com"},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
		{
			name:       "missing scope",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      clientID,
				Scope:         "",
				RedirectUris:  []string{"/", "https://example.com"},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
		{
			name:       "missing RedirectUris",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      clientID,
				Scope:         "scope",
				RedirectUris:  []string{},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
		{
			name:       "missing GrantTypes",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      clientID,
				Scope:         "scope",
				RedirectUris:  []string{"/", "https://example.com"},
				GrantTypes:    []string{},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
		{
			name:       "missing RedirectUris",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      clientID,
				Scope:         "scope",
				RedirectUris:  []string{"/", "https://example.com"},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
		{
			name:       "invalid ui",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      clientID,
				Scope:         "scope",
				RedirectUris:  []string{"/", "https://example.com"},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label": "l",
				},
			},
		},
		{
			name:       "invalid RedirectUris",
			clientName: clientName,
			client: &pb.Client{
				ClientId:      clientID,
				Scope:         "scope",
				RedirectUris:  []string{"htt://example.com"},
				GrantTypes:    []string{"GrantTypes"},
				ResponseTypes: []string{"ResponseTypes"},
				Ui: map[string]string{
					"label":       "l",
					"description": "d",
				},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if err := CheckClientIntegrity(tc.clientName, tc.client); err == nil {
				t.Errorf("CheckClientIntegrity(%s, %v) should fail", tc.clientName, tc.client)
			}
		})
	}
}
