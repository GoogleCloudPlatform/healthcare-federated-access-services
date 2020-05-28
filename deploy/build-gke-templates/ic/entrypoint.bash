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
# - DOMAIN: the DOMAIN can access hydra/ic
# - SERVICE_NAME: namespace in storage. eg. ic-staging, ic-prod.

export URL="https://${DOMAIN?}"

# Service type: dam or ic
export TYPE="ic"
# SERVICE_NAME allows different instances to use different resources, such as storage.
export SERVICE_NAME="${SERVICE_NAME?}"
# HYDRA_PUBLIC_URL sets the hydra public url for start login.
# TODO need to update after we deploy hydra on GCP.
export HYDRA_PUBLIC_URL="${URL?}"
export HYDRA_PUBLIC_URL_INTERNAL="${HYDRA_PUBLIC_URL_INTERNAL?}"
# HYDRA_ADMIN_URL sets the hydra admin url for callback.
# TODO need to update after we deploy hydra on GCP.
export HYDRA_ADMIN_URL="${HYDRA_ADMIN_URL?}"
export USE_HYDRA="true"
# CONFIG_PATH is the path used for reading and writing config files.
export CONFIG_PATH="deploy/config"
# STORAGE is one of: "memory", "datastore".
export STORAGE="datastore"

export IC_PORT="8080"
# SERVICE_DOMAIN determines the URL domain for identity provider redirects and issuer strings.
export SERVICE_DOMAIN="${DOMAIN?}"
# ACCOUNT_DOMAIN determines the URL domain for accounts (user@domain).
export ACCOUNT_DOMAIN="${DOMAIN?}"

cd /hcls-fa
./ic -alsologtostderr
