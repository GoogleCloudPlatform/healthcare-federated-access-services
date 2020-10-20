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

// Package secret contains helpers to access secrets in GCP secretmanager.
package secret

import (
	"context"
	"fmt"

	"cloud.google.com/go/secretmanager/apiv1" /* copybara-comment: secretmanager */

	pb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1" /* copybara-comment: service_go_proto */
)

// Client to access secret on gcp secretmanager.
type Client struct {
	client  *secretmanager.Client
	project string
}

// New creates client to access secret on gcp secretmanager.
func New(client *secretmanager.Client, project string) *Client {
	return &Client{
		client:  client,
		project: project,
	}
}

// GetSecret get the latest version of given key of secret.
func (s *Client) GetSecret(ctx context.Context, key string) (string, error) {
	name := fmt.Sprintf("projects/%s/secrets/%s/versions/latest", s.project, key)

	req := &pb.AccessSecretVersionRequest{
		Name: name,
	}

	resp, err := s.client.AccessSecretVersion(ctx, req)
	if err != nil {
		return "", err
	}
	return string(resp.Payload.Data), nil
}
