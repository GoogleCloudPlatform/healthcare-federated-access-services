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

// Binary ic_reset to reset the storage of an IC
package main

import (
	"context"
	"flag"
	"os"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ic" /* copybara-comment: ic */

	glog "github.com/golang/glog" /* copybara-comment */
)

func main() {
	args := make([]string, len(os.Args))
	copy(args, os.Args)
	flag.Parse()

	if len(args) < 3 {
		glog.Fatalf("Usage: ic_reset <project> <service> [path]")
	}
	project := args[1]
	service := args[2]
	path := "deploy/config"
	if len(args) > 3 {
		path = args[3]
	}

	store := dsstore.NewDatastoreStorage(context.Background(), project, service, path)

	ics := ic.NewService(&ic.Options{
		Domain:         "reset.example.org",
		ServiceName:    service,
		AccountDomain:  "reset.example.org",
		Store:          store,
		Encryption:     nil,
		UseHydra:       true,
		HydraAdminURL:  "https://reset.example.org",
		HydraPublicURL: "https://reset.example.org",
	})

	if err := ics.ImportFiles("FORCE_WIPE"); err != nil {
		glog.Fatalf("error importing files: %v", err)
	}
	glog.Infof("SUCCESS resetting IC service %q", service)
}
