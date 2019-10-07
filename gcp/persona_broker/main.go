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

// This package provides a persona broker service for offering a
// playground environment where users can log in and manage the system
// using personas. For configuration information see app.yaml.
package main

import (
	"os"

	glog "github.com/golang/glog"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona"
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys"
)

func main() {
	key := &testkeys.PersonaBrokerKey
	service := os.Getenv("DAM_SERVICE_NAME")
	if len(service) == 0 {
		service = "dam"
	}
	path := os.Getenv("CONFIG_PATH")
	if len(path) == 0 {
		path = "deploy/config"
	}
	oidcURL := os.Getenv("OIDC_URL")
	if len(oidcURL) == 0 {
		glog.Fatalf("OIDC_URL must be provided")
	}
	port := os.Getenv("PORT")
	broker, err := persona.NewBroker(oidcURL, key, service, path)
	if err != nil {
		glog.Fatalf("starting broker: %v", err)
	}
	broker.Serve(port)
}
