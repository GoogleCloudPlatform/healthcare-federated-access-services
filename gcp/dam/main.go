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
	"os"
	"os/signal"

	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/server" /* copybara-comment: server */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
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
	// hidePolicyBasis when set to true will not send policy basis via non-admin endpoints.
	hidePolicyBasis = os.Getenv("HIDE_POLICY_BASIS") != ""
	// hideRejectDetail when set to true will not send visa rejection detail to clients.
	hideRejectDetail = os.Getenv("HIDE_REJECTION_DETAILS") != ""

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

	serviceinfo.Project = project
	serviceinfo.Type = "dam"
	serviceinfo.Name = srvName

	var store storage.Store
	switch storageType {
	case "datastore":
		store = dsstore.NewDatastoreStorage(ctx, project, srvName, cfgPath)
	case "memory":
		store = storage.NewMemoryStorage(srvName, cfgPath)
	default:
		glog.Fatalf("Unknown storage type %q", storageType)
	}

	wh := saw.MustBuildAccountWarehouse(ctx, store)

	logger, err := logging.NewClient(ctx, project)
	if err != nil {
		glog.Fatalf("logging.NewClient() failed: %v", err)
	}
	logger.OnError = func(err error) {
		glog.Warningf("StackdriverLogging.Client.OnError: %v", err)
	}
	if useHydra {
		hydraAdminAddr = osenv.MustVar("HYDRA_ADMIN_URL")
		hydraPublicAddr = osenv.MustVar("HYDRA_PUBLIC_URL")
	}
	s := dam.NewService(&dam.Options{
		Domain:           srvAddr,
		ServiceName:      srvName,
		DefaultBroker:    defaultBroker,
		Store:            store,
		Warehouse:        wh,
		Logger:           logger,
		HidePolicyBasis:  hidePolicyBasis,
		HideRejectDetail: hideRejectDetail,
		UseHydra:         true,
		HydraAdminURL:    hydraAdminAddr,
		HydraPublicURL:   hydraPublicAddr,
	})

	srv := server.New("dam", port, s.Handler)
	srv.ServeUnblock()

	c := make(chan os.Signal, 1)
	// We'll accept graceful shutdowns when quit via SIGINT (Ctrl+C)
	// SIGKILL, SIGQUIT or SIGTERM (Ctrl+/) will not be caught.
	signal.Notify(c, os.Interrupt)

	// Block until we receive our signal.
	<-c

	srv.Shutdown()
}
