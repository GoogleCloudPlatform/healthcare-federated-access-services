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

// Binary hydra_reset to reset clients in hydra.
package main

import (
	"context"
	"net/http"
	"os"
	"time"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage" /* copybara-comment: gcp_storage */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/oathclients" /* copybara-comment: oathclients */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
	pb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/common/v1" /* copybara-comment: go_proto */
	dpb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/dam/v1" /* copybara-comment: go_proto */
	ipb "github.com/GoogleCloudPlatform/healthcare-federated-access-services/proto/ic/v1" /* copybara-comment: go_proto */
)

func loadClients(serviceType, serviceName, path string) (map[string]*pb.Client, map[string]string) {
	fs := storage.NewFileStorage(serviceName, path)

	if serviceType == "ic" {
		cfg := &ipb.IcConfig{}
		if err := fs.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
			glog.Fatalf("load config failed: %v", err)
		}
		secrets := &ipb.IcSecrets{}
		if err := fs.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
			glog.Fatalf("load secrets failed: %v", err)
		}

		return cfg.Clients, secrets.ClientSecrets
	}

	if serviceType == "dam" {
		cfg := &dpb.DamConfig{}
		if err := fs.Read(storage.ConfigDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, cfg); err != nil {
			glog.Fatalf("load config failed: %v", err)
		}
		secrets := &dpb.DamSecrets{}
		if err := fs.Read(storage.SecretsDatatype, storage.DefaultRealm, storage.DefaultUser, storage.DefaultID, storage.LatestRev, secrets); err != nil {
			glog.Fatalf("load secrets failed: %v", err)
		}

		return cfg.Clients, secrets.ClientSecrets
	}

	return nil, nil
}

func main() {
	useHydra := os.Getenv("USE_HYDRA") != ""
	if !useHydra {
		return
	}

	hydraAdminURL := os.Getenv("HYDRA_ADMIN_URL")
	if hydraAdminURL == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "HYDRA_ADMIN_URL")
	}

	serviceType := os.Getenv("TYPE")
	if serviceType != "ic" && serviceType != "dam" {
		glog.Fatalf("Environment variable %q must be set to ic or dam", "TYPE")
	}

	path := os.Getenv("CONFIG_PATH")
	if path == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "CONFIG_PATH")
	}

	serviceName := os.Getenv("SERVICE_NAME")
	if serviceName == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "SERVICE_NAME")
	}

	project := os.Getenv("PROJECT")
	if project == "" {
		glog.Fatalf("Environment variable %q must be set: see app.yaml for more information", "PROJECT")
	}

	clients, secrets := loadClients(serviceType, serviceName, path)

	store := gcp_storage.NewDatastoreStorage(context.Background(), project, serviceName, path)

	tx := store.LockTx(serviceType+"_hydra", 0*time.Second, nil)
	if tx == nil {
		glog.Fatalf("failed to reset hydra clients: cannot acquire storage lock")
	}
	defer tx.Finish()
	if err := oathclients.ResetClients(http.DefaultClient, hydraAdminURL, clients, secrets); err != nil {
		glog.Fatalf("failed to reset hydra clients: %v", err)
	}

	glog.Info("hydra clients reset finish.")
}
