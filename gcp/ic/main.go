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
	"cloud.google.com/go/kms/apiv1" /* copybara-comment: kms */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage" /* copybara-comment: gcp_storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ic" /* copybara-comment: ic */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpcrypt" /* copybara-comment: gcpcrypt */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */
)

var (
	// srvName is the name of this service.
	srvName = osenv.VarWithDefault("SERVICE_NAME", "ic")
	// srvAddr determines the URL for "issuer" field of objects issued by this and
	// the address identity providers use to redirect back to IC.
	srvAddr = osenv.MustVar("SERVICE_DOMAIN")
	// accDomain is the postfix for accounts created by IC.
	acctDomain = osenv.MustVar("ACCOUNT_DOMAIN")
	// cfgPath is the path to the config file.
	cfgPath = osenv.MustVar("CONFIG_PATH")
	// project is default GCP project for hosting storage,
	// config options can override this.
	project = osenv.MustVar("PROJECT")
	// storageType determines we should be using in-mem storage or not.
	storageType = osenv.MustVar("STORAGE")

	port = osenv.VarWithDefault("IC_PORT", "8080")

	useHydra = os.Getenv("USE_HYDRA") != ""
	// hydraAdminAddr is the address for the Hydra admin endpoint.
	hydraAdminAddr = ""
	// hydraPublicAddr is the address for the Hydra public endpoint.
	hydraPublicAddr = ""
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
		glog.Exitf("Unknown storage type: %q", storageType)
	}

	client, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		glog.Fatalf("kms.NewKeyManagementClient(ctx) failed: %v", err)
	}
	gcpkms, err := gcpcrypt.New(ctx, project, "global", srvName+"_ring", srvName+"_key", client)
	if err != nil {
		glog.Fatalf("gcpcrypt.New(ctx, %q, %q, %q, %q, client) failed: %v", project, "global", srvName+"_ring", srvName+"_key", err)
	}

	if useHydra {
		hydraAdminAddr = osenv.MustVar("HYDRA_ADMIN_URL")
		hydraPublicAddr = osenv.MustVar("HYDRA_PUBLIC_URL")
	}

	s := ic.NewService(ctx, srvAddr, acctDomain, hydraAdminAddr, hydraPublicAddr, store, gcpkms, useHydra)

	glog.Infof("IC listening on port %v", port)
	glog.Exit(http.ListenAndServe(":"+port, s.Handler))
}
