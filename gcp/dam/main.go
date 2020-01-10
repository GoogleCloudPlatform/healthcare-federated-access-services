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

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/internal/appengine" /* copybara-comment: appengine */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage" /* copybara-comment: gcp_storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

var (
	// srvName is the name of this service.
	srvName = envStrWithDefault("SERVICE_NAME", "dam")
	// srvAddr is the service URL in GA4GH passports targetting this service.
	srvAddr = mustEnvStr("DAM_URL")
	// cfgPath is the path to the config file.
	cfgPath = mustEnvStr("CONFIG_PATH")
	// project is default GCP project for hosting storage and service accounts,
	// config options can override this.
	project = mustEnvStr("PROJECT")
	// storageType determines we should be using in-mem storage or not.
	storageType = mustEnvStr("STORAGE")
	// hydraAdminAddr is the address for the Hydra.
	hydraAdminAddr = mustEnvStr("HYDRA_ADMIN_URL")
	// defaultBroker is the default Identity Broker.
	defaultBroker = mustEnvStr("DEFAULT_BROKER")

	useHydra = os.Getenv("USE_HYDRA") != ""
	port     = envStrWithDefault("DAM_PORT", "8081")
)

func main() {
	ctx := context.Background()

	var store storage.Store
	switch storageType {
	case "datastore":
		store = gcp_storage.NewDatastoreStorage(ctx, project, srvName, cfgPath)
	case "memory":
		store = storage.NewMemoryStorage(srvName, cfgPath)
	default:
		glog.Fatalf("Unknown storage type %q", storageType)
	}

	wh := appengine.MustBuildAccountWarehouse(ctx, store)
	s := dam.NewService(ctx, srvAddr, defaultBroker, hydraAdminAddr, store, wh, useHydra)

	glog.Infof("Listening on port %v", port)
	glog.Fatal(http.ListenAndServe(":"+port, s.Handler))
}

// mustEnvStr reads the value of an environment string variable.
// if it is not set, exits.
func mustEnvStr(name string) string {
	v := os.Getenv(name)
	if v == "" {
		glog.Exitf("Environment variable %q is not set.", name)
	}
	return v
}

// envStrWithDefault reads the value of an environment string variable.
// if it is not set, returns the provided default value.
func envStrWithDefault(name string, d string) string {
	v := os.Getenv(name)
	if v == "" {
		return d
	}
	return v
}
