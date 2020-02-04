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
	"flag"
	"net/http"
	"os"

	glog "github.com/golang/glog" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/internal/appengine" /* copybara-comment: appengine */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage" /* copybara-comment: gcp_storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

var (
	// srvName is the name of this service.
	srvName = osenv.VarWithDefault("SERVICE_NAME", "dam")
	// srvAddr is the service URL in GA4GH passports targetting this service.
	srvAddr = osenv.MustVar("DAM_URL")
	// cfgPath is the path to the config file.
	cfgPath = osenv.MustVar("CONFIG_PATH")
	// project is default GCP project for hosting storage and service accounts,
	// config options can override this.
	project = osenv.MustVar("PROJECT")
	// storageType determines we should be using in-mem storage or not.
	storageType = osenv.MustVar("STORAGE")
	// defaultBroker is the default Identity Broker.
	defaultBroker = osenv.MustVar("DEFAULT_BROKER")

	useHydra = os.Getenv("USE_HYDRA") != ""
	// hydraAdminAddr is the address for the Hydra admin endpoints.
	hydraAdminAddr = ""
	// hydraPublicAddr is the address for the Hydra public endpoints.
	hydraPublicAddr = ""
	port            = osenv.VarWithDefault("DAM_PORT", "8081")
)

func main() {
	flag.Parse()
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

	if useHydra {
		hydraAdminAddr = osenv.MustVar("HYDRA_ADMIN_URL")
		hydraPublicAddr = osenv.MustVar("HYDRA_PUBLIC_URL")
	}
	s := dam.NewService(&dam.Options{
		Domain:         srvAddr,
		DefaultBroker:  defaultBroker,
		Store:          store,
		Warehouse:      wh,
		UseHydra:       true,
		HydraAdminURL:  hydraAdminAddr,
		HydraPublicURL: hydraPublicAddr,
	})

	glog.Infof("DAM listening on port %v", port)
	glog.Fatal(http.ListenAndServe(":"+port, s.Handler))
}
