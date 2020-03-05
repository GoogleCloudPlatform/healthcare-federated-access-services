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

package dam

const (
	// ---------------------------------------------------------------------------
	// The following are the main DAM endpoints.
	// Users can retrive access tokens for resources they want using the following
	// OIDC and DAM token checkout endpoints.
	// ---------------------------------------------------------------------------

	// Redirected to here from Hydra login.
	hydraLoginPath = "/dam/login"
	// Redirected to here from Hydra consent.
	hydraConsentPath = "/dam/consent"
	// Redirected to here from Identity Broker.
	// TODO: rename to "accept" which is a more idiomatic OIDC name.
	loggedInPath = "/dam/oidc/loggedin"

	// resourceTokensPath: returns the batch of access tokens for the requested
	// resources.
	resourceTokensPath = "/dam/checkout"

	// ---------------------------------------------------------------------------
	// The following are administration endpoints for managing DAM.
	// ---------------------------------------------------------------------------

	// infoPath: metadata about the service, like versions of various services.
	// Required permission: admin
	infoPath = "/dam"

	// realms: for managing realms.
	realmPath = "/dam/v1alpha/{realm}"

	// processes: the state of various background processes running in DAM.
	// Required permission: admin
	processesPath = "/dam/v1alpha/{realm}/processes"
	processPath   = "/dam/v1alpha/{realm}/processes/{name}"

	// The following are used to manage configuration of DAM.
	// Required permission: admin
	// TODO: remove the sub-paths and use filter and update mask parameters instead.
	configPath                = "/dam/v1alpha/{realm}/config"
	configResourcePath        = "/dam/v1alpha/{realm}/config/resources/{name}"
	configViewPath            = "/dam/v1alpha/{realm}/config/resources/{resource}/views/{name}"
	configTrustedIssuerPath   = "/dam/v1alpha/{realm}/config/trustedIssuers/{name}"
	configTrustedSourcePath   = "/dam/v1alpha/{realm}/config/trustedSources/{name}"
	configPolicyPath          = "/dam/v1alpha/{realm}/config/policies/{name}"
	configOptionsPath         = "/dam/v1alpha/{realm}/config/options"
	configClaimDefPath        = "/dam/v1alpha/{realm}/config/claimDefinitions/{name}"
	configServiceTemplatePath = "/dam/v1alpha/{realm}/config/serviceTemplates/{name}"
	configClientPath          = "/dam/v1alpha/{realm}/config/clients/{name}"
	configTestPersonasPath    = "/dam/v1alpha/{realm}/config/testPersonas"
	configTestPersonaPath     = "/dam/v1alpha/{realm}/config/testPersonas/{name}"

	// ConfigReset: resets the config to its initial state read from configuration file.
	// Required permission: admin
	configResetPath = "/dam/v1alpha/{realm}/config/reset"

	// SyncClients: performs a sync of clients to Hydra.
	// Required permission: trusted client with "sync" scope defined in the config.
	syncClientsPath = "/dam/v1alpha/{realm}/clients:sync"

	// ConfigHistory: history of configuration changes.
	// Required permission: admin
	configHistoryPath         = "/dam/v1alpha/{realm}/config/history"
	configHistoryRevisionPath = "/dam/v1alpha/{realm}/config/history/{name}"

	// testPath: performs a set of tests for validity of the current configuration.
	// TODO: remove and perform tests at the time of config update and reject
	// update if it would put the configuration in an invalid state.
	testPath = "/dam/v1alpha/{realm}/tests"

	// End-point for managing consents. See "proto/tokens/v1/tokens.proto"
	consentsPath = "/consents"
	consentPath  = "/consents/"

	// ---------------------------------------------------------------------------
	// The following are read-only non-admin access to configurations of DAM.
	// ---------------------------------------------------------------------------
	// The following provide read-only access to non-admins for various parts of
	// DAM configuration. They filter out sensitive parts of the configuration.
	// See the configuration endpoints above.
	// TODO: remove these and reuse the config endpoint when the caller does not
	// have admin permission.
	clientPath            = "/dam/v1alpha/{realm}/client/{name}"
	resourcesPath         = "/dam/v1alpha/{realm}/resources"
	resourcePath          = "/dam/v1alpha/{realm}/resources/{name}"
	flatViewsPath         = "/dam/v1alpha/{realm}/flatViews"
	viewsPath             = "/dam/v1alpha/{realm}/resources/{name}/views"
	viewPath              = "/dam/v1alpha/{realm}/resources/{name}/views/{view}"
	rolesPath             = "/dam/v1alpha/{realm}/resources/{name}/views/{view}/roles"
	rolePath              = "/dam/v1alpha/{realm}/resources/{name}/views/{view}/roles/{role}"
	servicesPath          = "/dam/v1alpha/{realm}/services"
	translatorsPath       = "/dam/v1alpha/{realm}/passportTranslators"
	damRoleCategoriesPath = "/dam/v1alpha/{realm}/damRoleCategories"
	testPersonasPath      = "/dam/v1alpha/{realm}/testPersonas"
)
