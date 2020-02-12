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
# IC
################################################################################
function start_ic() {
  start_hydra

  # Service type: dam or ic
  export TYPE="ic"
  # SERVICE_NAME allows different instances to use different resources, such as storage.
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

  export IC_PORT="8000"
  # SERVICE_DOMAIN determines the URL domain for identity provider redirects and issuer strings.
  export SERVICE_DOMAIN="${SERVICE_NAME?}-dot-${PROJECT}.appspot.com"
  # ACCOUNT_DOMAIN determines the URL domain for accounts (user@domain).
  export ACCOUNT_DOMAIN="${SERVICE_NAME?}-dot-${PROJECT}.appspot.com"

  # Reset clients in hydra.
  cd /hcls-fa
  go run gcp/hydra_reset/main.go -alsologtostderr
  echo Reseted clients in HYDRA

  echo Starting IC
  cd /hcls-fa
  ./ic -alsologtostderr &
  echo Started IC

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
  export URLS_CONSENT="${URL?}/identity/consent"
  export URLS_LOGIN="${URL?}/identity/login"
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

start_ic

# Wait
sleep infinity
