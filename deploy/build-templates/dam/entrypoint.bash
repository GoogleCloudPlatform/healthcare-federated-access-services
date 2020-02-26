#!/bin/bash

# Copyright 2019 Google LLC
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

URL="https://${SERVICE_NAME?}-dot-${PROJECT?}.appspot.com"

################################################################################
# DAM
################################################################################
function start_dam() {
  start_hydra

  # SERVICE_NAME allows different instances to use different resources, such as storage.
  # It is common to keep this in sync with the YAML "service" name via $TYPE.
  export SERVICE_NAME="${SERVICE_NAME?}"
  # HYDRA_PUBLIC_URL sets the hydra public url for start login.
  # TODO need to update after we deploy hydra on GCP.
  export HYDRA_PUBLIC_URL="${URL?}"
  # HYDRA_ADMIN_URL sets the hydra admin url for callback.
  # TODO need to update after we deploy hydra on GCP.
  export HYDRA_ADMIN_URL="http://127.0.0.1:4445"
  export USE_HYDRA="true"
  # CONFIG_PATH is the path used for reading and writing config files.
  export CONFIG_PATH="deploy/config"
  # STORAGE is one of: "memory", "datastore".
  export STORAGE="datastore"

  export DAM_PORT="8000"
  # DAM_URL is the expected service URL in GA4GH passports targetted at this service.
  export DAM_URL="${URL?}"
  # DEFAULT_BROKER is the default identity broker.
  export DEFAULT_BROKER="default_ic"

  echo Starting DAM
  cd /hcls-fa
  ./dam -alsologtostderr &
  echo Started DAM

  start_nginx
}

################################################################################
# Hydra
################################################################################
function start_hydra() {
  echo Starting HYDRA
  # Use jwt access tokem
  export OAUTH2_ACCESS_TOKEN_STRATEGY="jwt"
  # Encryption support in database
  # TODO: should read from cloud store
  export SECRETS_SYSTEM="123456789012345657890"
  # CORS for public
  export SERVE_PUBLIC_CORS_ENABLED="true"
  export SERVE_PUBLIC_CORS_ALLOWED_ORIGINS="*"
  # issuer URL
  export URLS_SELF_ISSUER="${URL?}"
  # Login and consent app
  export URLS_CONSENT="${URL?}/dam/consent"
  export URLS_LOGIN="${URL?}/dam/login"
  # Database connect
  export DSN="postgres://hydra:hydra@172.17.0.1:1234/${TYPE?}?sslmode=disable"

  # Setup database for hydra.
  cd /hydra
  ./hydra migrate sql --yes $DSN

  # Start hydra
  # use --dangerous-force-http because GAE take care of https.
  ./hydra serve all --dangerous-force-http &
  sleep 10
  echo Started HYDRA
}

################################################################################
# Ngnix
################################################################################
function start_nginx() {
  echo Starting NGINX
  cd /
  nginx
  echo Started NGINX
}

start_dam

# Wait
sleep infinity
