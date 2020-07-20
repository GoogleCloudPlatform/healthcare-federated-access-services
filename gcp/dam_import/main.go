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
	"strings"

	"google.golang.org/grpc/codes" /* copybara-comment */
	"google.golang.org/grpc/status" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
)

func main() {
	pre := flag.String("account_prefix", "", "when a wipe is requested, accounts matching this prefix override will be removed")
	path := flag.String("path", "deploy/config", "specifies the relative or absolute path to the config file root")
	wipe := flag.String("wipe", "", "specify 'unsafe_wipe_in_non_production' to remove all data for the service from the storage layer first (DO NOT USE IN PRODUCTION)")

	flag.Parse()
	args := flag.Args()

	if len(args) != 3 {
		glog.Exitf("Usage: dam_import -wipe=... -path=<config_root> -account_prefix=<service_account_prefix_to_delete> <project> <environment> <import_type>")
	}
	project := args[0]
	env := args[1]
	importType := args[2]
	envPrefix := ""
	service := "dam"
	if len(env) > 0 {
		envPrefix = "-" + env
		service += envPrefix
	}
	accountPrefix := "ic" + envPrefix + "-dot-"
	if *pre != "" {
		accountPrefix = *pre
	}
	ctx := context.Background()
	store := dsstore.NewStore(context.Background(), project, service, *path)
	wh := saw.MustNew(ctx, store)
	vars := map[string]string{
		"${YOUR_PROJECT_ID}":  project,
		"${YOUR_ENVIRONMENT}": envPrefix,
	}
	if *wipe != "" {
		if *wipe != "unsafe_wipe_in_non_production" {
			glog.Exitf("attempted wipe failed: only works if specific safety value set. See -h for help.")
		}
		glog.Infof("WIPE STORAGE FOR SERVICE %q...", service)
		if _, err := store.Wipe(ctx, storage.AllRealms, 0, 0); err != nil {
			glog.Exitf("error wiping storage for service %q: %v", service, err)
		}
		glog.Infof("Wipe complete")
	}

	importConfig := false
	importSecrets := false
	importPermission := false

	switch importType {
	case "all":
		importConfig = true
		importSecrets = true
		importPermission = true
	case "config":
		importConfig = true
	case "security":
		importSecrets = true
	case "permission":
		importPermission = true
	default:
		glog.Exitf("unknown importing config type: %s", importType)
	}

	if err := dam.ImportConfig(store, service, wh, vars, importConfig, importSecrets, importPermission); err != nil {
		glog.Exitf("error importing files: %v", err)
	}

	if *wipe != "" {
		cleanupServiceAccounts(ctx, accountPrefix, project, store)
	}

	glog.Infof("SUCCESS resetting DAM service %q", service)
}

func cleanupServiceAccounts(ctx context.Context, accountPrefix, project string, store *dsstore.Store) {
	wh := saw.MustNew(ctx, store)
	var (
		removed, skipped, errors int
		emails                   []string
	)
	maxErrors := 20
	aborted := ""

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	accounts, err := wh.GetServiceAccounts(ctx, project)
	if err != nil {
		glog.Errorf("fetching service accounts from project %q failed: %v", project, err)
		return
	}

	for a := range accounts {
		// DAM adds service account DisplayName of the form: subject|service_full_path
		// so pull out the service_full_path and match on the accountPrefix provided.
		parts := strings.SplitN(a.DisplayName, "|", 2)
		if len(parts) < 2 || !strings.HasPrefix(parts[1], accountPrefix) {
			skipped++
			continue
		}
		emails = append(emails, a.ID)
	}

	for _, email := range emails {
		err := wh.RemoveServiceAccount(ctx, project, email)
		switch status.Code(err) {
		case codes.OK:
			removed++

		case codes.NotFound:
			glog.Infof("deleting service account %q on project %q: acccount does not exist.", email, project)

		default:
			errors++
			if errors >= maxErrors {
				aborted = "+ (aborted early)"
				break
			}
			if errors < 3 {
				glog.Errorf("deleting service account %q on project %q failed: %v", email, project, err)
			}
		}
	}
	glog.Infof("status of removing service accounts: project %q, prefix %q, matched %d, removed %d, skipped %d, errors %d%s", project, accountPrefix, len(emails), removed, skipped, errors, aborted)
}
