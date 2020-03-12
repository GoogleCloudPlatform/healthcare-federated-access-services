#!/bin/bash

# Copyright 2020 Google LLC
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

# Require ENVs:
# - URL: the URL can access hydra
# - DSN: format: "postgres://${DB_USER?}:${DB_PASSWORD?}@${DB_PRIVATE_IP}:${DB_PORT}/${DB_NAME?}?sslmode=disable"

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

# Setup database for hydra.
cd /hydra
./hydra migrate sql --yes $DSN

# Start hydra
# use --dangerous-force-http because GCLB take care of https.
./hydra serve all --dangerous-force-http
