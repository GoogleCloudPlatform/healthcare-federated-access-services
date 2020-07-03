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
	"os/signal"
	"strings"

	"cloud.google.com/go/kms/apiv1" /* copybara-comment: kms */
	"cloud.google.com/go/logging" /* copybara-comment: logging */
	"github.com/gorilla/mux" /* copybara-comment */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/aws" /* copybara-comment: aws */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dam" /* copybara-comment: dam */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/dsstore" /* copybara-comment: dsstore */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/grpcutil" /* copybara-comment: grpcutil */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/httputils" /* copybara-comment: httputils */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/hydraproxy" /* copybara-comment: hydraproxy */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpcrypt" /* copybara-comment: gcpcrypt */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/kms/gcpsign" /* copybara-comment: gcpsign */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/osenv" /* copybara-comment: osenv */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/saw" /* copybara-comment: saw */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/server" /* copybara-comment: server */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/serviceinfo" /* copybara-comment: serviceinfo */
	"github.com/GoogleCloudPlatform/healthcare-federated-access-services/lib/storage" /* copybara-comment: storage */

	glog "github.com/golang/glog" /* copybara-comment */
	lgrpcpb "google.golang.org/genproto/googleapis/logging/v2" /* copybara-comment: logging_go_grpc */
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

	// skipInformationReleasePage is useful if IC and DAM provided by same org.
	// Use env var "SKIP_INFORMATION_RELEASE_PAGE" = true to set.
	skipInformationReleasePage = os.Getenv("SKIP_INFORMATION_RELEASE_PAGE") == "true"

	// consentDashboardURL is url to frontend consent dashboard, will replace
	// ${USER_ID} with userID. If it is not set point to howto doc on github
	// repo.
	consentDashboardURL = osenv.VarWithDefault("CONSENT_DASHBOARD_URL", "https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/0f366e73284377571bc314da7666e4b14233c3fa/howto.md#how-do-i-revoke-a-remembered-consent")

	useHydra = os.Getenv("USE_HYDRA") != ""
	// hydraAdminAddr is the address for the Hydra admin endpoints.
	hydraAdminAddr = ""
	// hydraPublicAddr is the address for the Hydra public endpoints.
	hydraPublicAddr = ""
	// hydraPublicAddrInternal is the address for the Hydra public endpoint in the internal traffic.
	hydraPublicAddrInternal = ""
	port                    = osenv.VarWithDefault("DAM_PORT", "8081")

	cfgVars = map[string]string{
		"${YOUR_PROJECT_ID}":  project,
		"${YOUR_ENVIRONMENT}": envPrefix(srvName),
	}

	// sldAddr is the address for Stackdriver Logging API.
	sdlAddr = osenv.VarWithDefault("SDL_ADDR", "logging.googleapis.com:443")
)

func main() {
	flag.Parse()
	ctx := context.Background()

	serviceinfo.Project = project
	serviceinfo.Type = "dam"
	serviceinfo.Name = srvName

	sdlcc := grpcutil.NewGRPCClient(ctx, sdlAddr)
	defer sdlcc.Close()
	sdlc := lgrpcpb.NewLoggingServiceV2Client(sdlcc)

	var store storage.Store
	switch storageType {
	case "datastore":
		store = dsstore.NewStore(ctx, project, srvName, cfgPath)
	case "memory":
		store = storage.NewMemoryStorage(srvName, cfgPath)
		// Import and resolve template variables, if any.
		if err := dam.ImportConfig(store, srvName, nil, cfgVars, true, true, true); err != nil {
			glog.Exitf("dam.ImportConfig(_, %q, _) failed: %v", srvName, err)
		}
	default:
		glog.Exitf("Unknown storage type %q", storageType)
	}

	wh := saw.MustNew(ctx, store)

	kmsClient, err := kms.NewKeyManagementClient(ctx)
	if err != nil {
		glog.Exitf("kms.NewKeyManagementClient(ctx) failed: %v", err)
	}
	gcpSigner, err := gcpsign.New(ctx, project, "global", srvName+"_sign_ring", srvName+"_key", kmsClient)
	if err != nil {
		glog.Exitf("gcpcrypt.New(ctx, %q, %q, %q, %q, kmsClient) failed: %v", project, "global", srvName+"_sign_ring", srvName+"_key", err)
	}
	gcpEncryption, err := gcpcrypt.New(ctx, project, "global", srvName+"_ring", srvName+"_key", kmsClient)
	if err != nil {
		glog.Exitf("gcpcrypt.New(ctx, %q, %q, %q, %q, kmsClient) failed: %v", project, "global", srvName+"_ring", srvName+"_key", err)
	}

	logger, err := logging.NewClient(ctx, project)
	if err != nil {
		glog.Fatalf("logging.NewClient() failed: %v", err)
	}
	logger.OnError = func(err error) {
		glog.Warningf("StackdriverLogging.Client.OnError: %v", err)
	}

	var hyproxy *hydraproxy.Service
	if useHydra {
		hydraAdminAddr = osenv.MustVar("HYDRA_ADMIN_URL")
		hydraPublicAddr = osenv.MustVar("HYDRA_PUBLIC_URL")
		hydraPublicAddrInternal := osenv.MustVar("HYDRA_PUBLIC_URL_INTERNAL")

		hyproxy, err = hydraproxy.New(http.DefaultClient, hydraAdminAddr, hydraPublicAddrInternal, store)
		if err != nil {
			glog.Exitf("hydraproxy.New failed: %v", err)
		}
	}

	awsClient, err := aws.NewAPIClient()
	if err != nil {
		glog.Fatalf("aws.NewAPIClient failed: %v", err)
	}

	r := mux.NewRouter()

	s := dam.New(r, &dam.Options{
		Domain:                     srvAddr,
		ServiceName:                srvName,
		DefaultBroker:              defaultBroker,
		Store:                      store,
		Warehouse:                  wh,
		AWSClient:                  awsClient,
		ServiceAccountManager:      wh,
		Logger:                     logger,
		SDLC:                       sdlc,
		AuditLogProject:            project,
		HidePolicyBasis:            hidePolicyBasis,
		HideRejectDetail:           hideRejectDetail,
		SkipInformationReleasePage: skipInformationReleasePage,
		ConsentDashboardURL:        consentDashboardURL,
		UseHydra:                   true,
		HydraAdminURL:              hydraAdminAddr,
		HydraPublicURL:             hydraPublicAddr,
		HydraPublicProxy:           hyproxy,
		Signer:                     gcpSigner,
		Encryption:                 gcpEncryption,
	})

	r.HandleFunc("/liveness_check", httputils.LivenessCheckHandler)

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

func envPrefix(name string) string {
	if strings.Contains(name, "-") {
		return "-" + strings.SplitN(name, "-", 2)[1]
	}
	return ""
}
