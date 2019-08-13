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

// This package provides a single-host reverse proxy that rewrites bearer
// tokens in Authorization headers to be Google Cloud Platform access tokens.
// For configuration information see app.yaml.
package main

import (
	"context"
	"log"
	"net/http"
	"os"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/ic"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/module"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/storage"
	//ga4gh "github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ga4gh"
)

const (
	ProductName        = "Identity Concentrator"
	DefaultServiceName = "ic"
)

func main() {
	ctx := context.Background()
	domain := os.Getenv("SERVICE_DOMAIN")
	if domain == "" {
		log.Fatalf("Environment variable %q must be set: see app.yaml for more information", "SERVICE_DOMAIN")
	}
	acctDomain := os.Getenv("ACCOUNT_DOMAIN")
	if acctDomain == "" {
		log.Fatalf("Environment variable %q must be set: see app.yaml for more information", "ACCOUNT_DOMAIN")
	}
	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		log.Fatalf("Environment variable %q must be set: see app.yaml for more information", "CONFIG_PATH")
	}
	project := os.Getenv("PROJECT")
	if project == "" {
		log.Fatalf("Environment variable %q must be set: see app.yaml for more information", "PROJECT")
	}
	storeName := os.Getenv("STORAGE")
	if storeName == "" {
		log.Fatalf("Environment variable %q must be set: see app.yaml for more information", "STORAGE")
	}
	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		serviceName = DefaultServiceName
	}
	var store storage.Store
	switch storeName {
	case "datastore":
		store = gcp_storage.NewDatastoreStorage(ctx, project, serviceName, path)
	case "memory":
		store = storage.NewMemoryStorage(serviceName, path)
	default:
		log.Fatalf("environment variable %q: unknown storage type %q", "STORAGE", storeName)
	}

	module := module.NewPlaygroundModule(os.Getenv("PERSONA_DAM_URL"), os.Getenv("PERSONA_DAM_CLIENT_ID"), os.Getenv("PERSONA_DAM_CLIENT_SECRET"))
	s := ic.NewService(domain, acctDomain, store, module)
	port := os.Getenv("PORT")
	if len(port) == 0 {
		port = "8080"
	}
	log.Printf("%s using port %v", ProductName, port)
	log.Fatal(http.ListenAndServe(":"+port, s.Handler))
}
