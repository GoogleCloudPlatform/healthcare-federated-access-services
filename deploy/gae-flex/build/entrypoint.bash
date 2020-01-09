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

URL="https://${TYPE?}-dot-${PROJECT}.appspot.com"

#################
# Hydra Settings
#################

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
# Database connect
export DSN="postgres://hydra:hydra@172.17.0.1:1234/${TYPE?}?sslmode=disable"

########################
# IC/DAM share settings
########################

# SERVICE_NAME allows different instances to use different resources, such as storage.
# It is common to keep this in sync with the "service" entry above.
export SERVICE_NAME="${TYPE?}"
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


if [ $TYPE = "ic" ]; then
  #################
  # IC Settings
  #################

  export IC_PORT="8000"
  # SERVICE_DOMAIN determines the URL domain for identity provider redirects and issuer strings.
  export SERVICE_DOMAIN="${TYPE?}-dot-${PROJECT}.appspot.com"
  # ACCOUNT_DOMAIN determines the URL domain for accounts (user@domain).
  export ACCOUNT_DOMAIN="ic-dot-${PROJECT}.appspot.com"
  # PERSONA_DAM_URL sets the playground URL where personas are fetched from for playground logins.
  export PERSONA_DAM_URL="https://dam-dot-${PROJECT}.appspot.com"
  # PERSONA_DAM_CLIENT_ID is the IC's client ID for use with the PERSONA_DAM_URL service.
  export PERSONA_DAM_CLIENT_ID="1f8ff367-3950-48c2-9358-781f9adff70c"
  # PERSONA_DAM_CLIENT_SECRET is the IC's client secret for use with the PERSONA_DAM_URL service.
  export PERSONA_DAM_CLIENT_SECRET="d3d3a837-168e-497f-b1c5-557f9833c948"

  #################
  # Hydra Settings
  #################

  # Login and consent app
  export URLS_CONSENT="${URL?}/identity/consent"
  export URLS_LOGIN="${URL?}/identity/login"

elif [ $TYPE = "dam" ]; then
  #################
  # DAM Settings
  #################

  export DAM_PORT="8000"
  # DAM_URL is the expected service URL in GA4GH passports targetted at this service.
  export DAM_URL="${URL?}"
  # DEFAULT_BROKER is the default identity broker.
  export DEFAULT_BROKER="ic"

  #################
  # Hydra Settings
  #################

  # Login and consent app
  export URLS_CONSENT="${URL?}/dam/consent"
  export URLS_LOGIN="${URL?}/dam/login"

fi

# Setup database for hydra.
cd /hydra
./hydra migrate sql --yes $DSN

# Start hydra
# use --dangerous-force-http because GAE take care of https.
./hydra serve all --dangerous-force-http &

# Start ic or dam
cd /healthcare-federated-access-services
if [ $TYPE = "ic" ]; then
  ./ic &
elif [ $TYPE = "dam" ]; then
  ./dam &
fi

# Reset clients in hydra.
go run gcp/hydra_reset/main.go

# Start nginx at the end.
cd /
nginx -g 'daemon off;'
