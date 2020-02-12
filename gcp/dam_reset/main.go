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
	"flag"
	"os"
	"strings"

	glog "github.com/golang/glog" /* copybara-comment */
	"google.golang.org/api/iam/v1" /* copybara-comment: iam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/adapter/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
)

func main() {
	args := make([]string, len(os.Args))
	copy(args, os.Args)
	flag.Parse()

	if len(args) < 3 {
		glog.Fatalf("Usage: dam_reset <project> <service> [path] [service_account_prefix]")
	}
	project := args[1]
	service := args[2]
	path := "deploy/config"
	accountPrefix := ""
	if len(args) > 3 {
		path = args[3]
	}
	if len(args) > 4 {
		accountPrefix = args[4]
	}

	ctx := context.Background()
	store := dsstore.NewDatastoreStorage(context.Background(), project, service, path)
	dams := dam.NewService(&dam.Options{
		Domain:         "reset.example.org",
		ServiceName:    service,
		DefaultBroker:  "no-broker",
		Store:          store,
		Warehouse:      nil,
		UseHydra:       true,
		HydraAdminURL:  "reset.example.org",
		HydraPublicURL: "reset.example.org",
	})

	if err := dams.ImportFiles("FORCE_WIPE"); err != nil {
		glog.Fatalf("error importing files: %v", err)
	}

	if len(accountPrefix) != 0 {
		cleanupServiceAccounts(ctx, accountPrefix, project, store)
	}

	glog.Infof("SUCCESS resetting DAM service %q", service)
}

func cleanupServiceAccounts(ctx context.Context, accountPrefix, project string, store *dsstore.DatastoreStorage) {
	wh := saw.MustBuildAccountWarehouse(ctx, store)
	var (
		removed, skipped, errors int
		emails                   []string
	)
	maxErrors := 20
	aborted := ""
	err := wh.GetServiceAccounts(ctx, project, func(sa *iam.ServiceAccount) bool {
		// DAM adds service account DisplayName of the form: subject|service_full_path
		// so pull out the service_full_path and match on the accountPrefix provided.
		parts := strings.SplitN(sa.DisplayName, "|", 2)
		if len(parts) < 2 || !strings.HasPrefix(parts[1], accountPrefix) {
			skipped++
			return true
		}
		emails = append(emails, sa.Email)
		return true
	})
	if err != nil {
		glog.Errorf("fetching service accounts from project %q failed: %v", project, err)
		return
	}
	for _, email := range emails {
		if err := wh.RemoveServiceAccount(ctx, project, email); err != nil {
			if errors < 3 {
				glog.Errorf("deleting service account %q on project %q failed: %v", email, project, err)
			}
			errors++
			if errors >= maxErrors {
				aborted = "+ (aborted early)"
				break
			}
		} else {
			removed++
		}
	}
	glog.Infof("status of removing service accounts: project %q, prefix %q, matched %d, removed %d, skipped %d, errors %d%s", project, accountPrefix, len(emails), removed, skipped, errors, aborted)
}
