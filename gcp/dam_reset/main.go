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

// Binary dam_reset to reset the storage of a DAM
package main

import (
	"context"
	"os"

	glog "github.com/golang/glog"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/gcp/storage"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam"
)

func main() {
	if len(os.Args) < 3 {
		glog.Fatalf("Usage: dam_reset <project> <service>")
	}
	project := os.Args[1]
	service := os.Args[2]
	path := "deploy/config"

	store := gcp_storage.NewDatastoreStorage(context.Background(), project, service, path)
	dams := dam.NewService(context.Background(), "reset.example.org", "reset.example.org", "reset.example.org", store, nil, false)

	if err := dams.ImportFiles("FORCE_WIPE"); err != nil {
		glog.Fatalf("error importing files: %v", err)
	}
	glog.Infof("SUCCESS reseting DAM service %q", service)
}
