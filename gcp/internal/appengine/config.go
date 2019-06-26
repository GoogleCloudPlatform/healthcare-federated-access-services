// Copyright 2018 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package appengine provides common functionality for applications running on
// Google Cloud Platform's appengine.
package appengine

import (
	"context"
	"log"
	"os"

	"golang.org/x/oauth2/google"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/clouds"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"
)

// MustBuildAccountWarehouse builds a *gcp.AccountWarehouse from the
// environment variables PROJECT, ROLE, and SCOPES.  It panics on failure.
func MustBuildAccountWarehouse(ctx context.Context, store storage.StorageInterface) clouds.ResourceTokenCreator {
	client, err := google.DefaultClient(context.Background(), "https://www.googleapis.com/auth/cloud-platform")
	if err != nil {
		log.Fatalf("Error creating HTTP client: %v", err)
		return nil
	}

	wh, err := gcp.NewAccountWarehouse(client, store)
	if err != nil {
		log.Fatalf("Error creating account warehouse: %v", err)
		return nil
	}
	return wh
}

func mustGetenv(key string) string {
	v := os.Getenv(key)
	if v == "" {
		log.Fatalf("Environment variable %q must be set: see app.yaml for more information", key)
	}
	return v
}
