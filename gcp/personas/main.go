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
	"flag"
	"net/http"

	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputil" /* copybara-comment: httputil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/persona" /* copybara-comment: persona */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/testkeys" /* copybara-comment: testkeys */

	glog "github.com/golang/glog" /* copybara-comment */
)

var (
	cfgPath  = osenv.VarWithDefault("CONFIG_PATH", "deploy/config")
	service  = osenv.VarWithDefault("DAM_SERVICE_NAME", "dam")
	oidcAddr = osenv.MustVar("OIDC_URL")
	port     = osenv.VarWithDefault("PERSONAS_PORT", "8090")
	project  = osenv.MustVar("PROJECT")
	srvName  = osenv.MustVar("TYPE")
)

func main() {
	flag.Parse()

	serviceinfo.Project = project
	serviceinfo.ServiceType = "persona"
	serviceinfo.ServiceName = srvName

	broker, err := persona.NewBroker(oidcAddr, &testkeys.PersonaBrokerKey, service, cfgPath, true)
	if err != nil {
		glog.Exitf("persona.NewBroker() failed: %v", err)
	}

	broker.Handler.HandleFunc("/liveness_check", httputil.LivenessCheckHandler)

	glog.Infof("Persona Broker using port %v", port)
	glog.Exit(http.ListenAndServe(":"+port, broker.Handler))
}
