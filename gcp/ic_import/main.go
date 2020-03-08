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

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/ic" /* copybara-comment: ic */

	glog "github.com/golang/glog" /* copybara-comment */
)

func main() {
	path := flag.String("path", "deploy/config", "specifies the relative or absolute path to the config file root")

	flag.Parse()
	args := flag.Args()

	if len(args) != 2 {
		glog.Exitf("Usage: ic_import -path=<config_root> <project> <environment>")
	}
	project := args[0]
	env := args[1]
	envPrefix := ""
	service := "ic"
	if len(env) > 0 {
		envPrefix = "-" + env
		service += envPrefix
	}
	store := dsstore.NewStore(context.Background(), project, service, *path)

	vars := map[string]string{
		"${YOUR_PROJECT_ID}":  project,
		"${YOUR_ENVIRONMENT}": envPrefix,
	}

	if err := ic.ImportConfig(store, service, vars); err != nil {
		glog.Exitf("error importing files: %v", err)
	}
	glog.Infof("SUCCESS resetting IC service %q", service)
}
