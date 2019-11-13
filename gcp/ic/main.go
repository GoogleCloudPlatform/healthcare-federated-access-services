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

// This package provides a single-host reverse proxy that rewrites bearer
// tokens in Authorization headers to be Google Cloud Platform access tokens.
// For configuration information see app.yaml.
package main

import (
	"context"
	"net/http"
	"os"

	glog "github.com/golang/glog"
	"cloud.google.com/go/kms/apiv1"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ic"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpcrypt"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage"
)

const (
	ProductName        = "Identity Concentrator"
	DefaultServiceName = "ic"
)

func main() {
	ctx := context.Background()
	domain := os.Getenv("SERVICE_DOMAIN")
	if domain == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "SERVICE_DOMAIN")
	}
	acctDomain := os.Getenv("ACCOUNT_DOMAIN")
	if acctDomain == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "ACCOUNT_DOMAIN")
	}
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "CONFIG_PATH")
	}
	project := os.Getenv("PROJECT")
	if project == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "PROJECT")
	}
	storeName := os.Getenv("STORAGE")
	if storeName == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "STORAGE")
	}
	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	hydraAdminURL := os.Getenv("HYDRA_ADMIN_URL")
	if hydraAdminURL == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "HYDRA_ADMIN_URL")
	}
	// TODO will remove this flag after hydra integration complete.
	useHydra := os.Getenv("USE_HYDRA") != ""

	var store storage.Store
	switch storeName {
	case "datastore":
		store = gcp_storage.NewDatastoreStorage(ctx, project, serviceName, path)
	case "memory":
		store = storage.NewMemoryStorage(serviceName, path)
	default:
		glog.Fatalf("environment variable %q: unknown storage type %q", "STORAGE", storeName)
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		glog.Fatalf("NewKeyManagementClient(ctx, clientOpt) failed: %v", err)
	}
	gcpkms, err := gcpcrypt.New(ctx, project, "global", serviceName+"_ring", serviceName+"_key", client)
	if err != nil {
		glog.Fatalf("gcpcrypt.New(ctx, %q, %q, %q, %q, client): %v", project, "global", serviceName+"_ring", serviceName+"_key", err)
	}

	s := ic.NewService(ctx, domain, acctDomain, hydraAdminURL, store, gcpkms, useHydra)
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}
	glog.Infof("%s using port %v", ProductName, port)
	glog.Fatal(http.ListenAndServe(":"+port, s.Handler))
}
