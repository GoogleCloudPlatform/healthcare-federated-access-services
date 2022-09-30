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

// Package main contains a manual test for secret manager.
package main

import (
	"context"
	"flag"
	"fmt"

	"cloud.google.com/go/secretmanager/apiv1" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/secret" /* copybara-comment: secret */

	glog "github.com/golang/glog" /* copybara-comment */
	rpb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1" /* copybara-comment: resources_go_proto */
	spb "google.golang.org/genproto/googleapis/cloud/secretmanager/v1" /* copybara-comment: service_go_proto */
)

var (
	project = flag.String("project", "", "project used to run the test")
)

const (
	key     = "testkey"
	payload = "this-is-a-secret"
)

func main() {
	flag.Parse()

	// add the key to project
	ctx := context.Background()
	client, err := secretmanager.NewClient(ctx)
	if err != nil {
		glog.Fatalf("failed to create secretmanager client: %v", err)
	}

	createReq := &spb.CreateSecretRequest{
		Parent:   fmt.Sprintf("projects/%s", *project),
		SecretId: key,
		Secret: &rpb.Secret{
			Replication: &rpb.Replication{
				Replication: &rpb.Replication_Automatic_{
					Automatic: &rpb.Replication_Automatic{},
				},
			},
		},
	}
	if _, err := client.CreateSecret(ctx, createReq); err != nil {
		glog.Fatalf("failed to create secret: %v", err)
	}

	addReq := &spb.AddSecretVersionRequest{
		Parent: fmt.Sprintf("projects/%s/secrets/%s", *project, key),
		Payload: &rpb.SecretPayload{
			Data: []byte(payload),
		},
	}

	if _, err = client.AddSecretVersion(ctx, addReq); err != nil {
		glog.Fatalf("failed to add secret version: %v", err)
	}

	c := secret.New(client, *project)
	got, err := c.GetSecret(ctx, key)
	if err != nil {
		glog.Fatalf("GetSecret() failed: %v", err)
	}

	if got != payload {
		glog.Errorf("secret = %s, wants %s", got, payload)
	}
}
