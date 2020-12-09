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

GREEN="\e[32m"
RED="\e[31m"
YELLOW="\e[33m"
RESET="\e[0m"

PROJECT=${PROJECT}
DB_USER=hydra
DB_PASSWORD=hydra

print_usage() {
  echo -e ${RED?}'Usage: prepare_project [-h] [-p project_id]'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
}

while getopts ':hp:' flag; do
  case "${flag}" in
    h) print_usage
       exit 1 ;;
    p) PROJECT="${OPTARG}" ;;
    *) echo -e ${RED?}'Unknown flag: -'${flag}${RESET?}
       print_usage
       exit 1 ;;
  esac
done

if [[ "${PROJECT}" == "" ]]; then
  echo -e ${RED?}'Must provide a project via $PROJECT or -p project'${RESET?}
  print_usage
  exit 1
fi

PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")
if [[ "$?" != 0 ]]; then
  exit 1
fi

echo -e ${YELLOW?} '!!! Warning:'
echo -e 'This script is still under development, many steps need to be done manually and it only supports IC for now.'
echo
echo -e 'Complete following steps on GCP console before start:'
echo -e '- Create gke cluster manully named "hcls-fa": https://console.cloud.google.com/kubernetes/list'
echo -e '  - with full access GCP api scope, in Node Pools - security, select "Compute Engine default service account" as Service Account and select "Allow full access to all Cloud APIs."'
echo -e '  - at least 3 nodes node pool.'
echo -e '- Enable "datastore mode" datastore: https://console.cloud.google.com/datastore/welcome'
echo -e '- Reserve Static IP: https://console.cloud.google.com/networking/addresses'
echo -e '- Bind your domain to the static ip reserved, run `nslookup your.doamin.to.ic` to verify before next step'
echo -e '- Fill your domain to deploy/build-gke-template/certificate.yaml and run `kubectl apply -f deploy/build-gke-template/certificate.yaml` to request https cert'
echo -e '- Config a OAuth screen: https://console.cloud.google.com/apis/credentials/consent?project='${PROJECT?}', see documentation at https://developers.google.com/identity/protocols/OAuth2'
echo -e '- Create OAuth client credentials and add redirect url (format: https://your.doamin.to.ic/identity/loggedin): https://console.cloud.google.com/apis/credentials?project='${PROJECT?}
echo
echo -e 'Press Enter to continue...'
echo -e ${RESET?}
read

echo -e ${GREEN?}'Preparing the GCP project '${PROJECT?}' for deployment.'${RESET?}
# Enbable the required APIs.
echo -e ${GREEN?}'Enabling the required APIs.'${RESET?}

gcloud services enable --project=${PROJECT?}\
  container.googleapis.com \
  sql-component.googleapis.com \
  sqladmin.googleapis.com \
  datastore.googleapis.com \
  iam.googleapis.com \
  cloudbuild.googleapis.com \
  bigquery.googleapis.com \
  storage-component.googleapis.com \
  cloudkms.googleapis.com \
  servicenetworking.googleapis.com

# Create a GAE app.
gcloud container clusters get-credentials hcls-fa --zone=us-central1-a

# Grant the required permissions.
echo -e ${GREEN?}'Granting the required permissions.'${RESET?}

gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT_NUMBER?}-compute@developer.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT_NUMBER?}-compute@developer.gserviceaccount.com --role roles/cloudkms.signerVerifier
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT_NUMBER?}-compute@developer.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT_NUMBER?}-compute@developer.gserviceaccount.com --role roles/cloudsql.client
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT_NUMBER?}-compute@developer.gserviceaccount.com --role roles/editor
gcloud projects add-iam-policy-binding -q ${PROJECT?} \
  --member serviceAccount:${PROJECT_NUMBER?}-compute@developer.gserviceaccount.com --role roles/resourcemanager.projectIamAdmin

# TODO: make region configurable.

# Create a datastore index to power related queries.
gcloud datastore indexes create deploy/index.yaml --project=${PROJECT?} --quiet

# Setup Cloud SQL
# Create a CloudSQL db-f1-micro (memory=128M, disk=250G) postgres 11 instance in us-central-1.
echo -e ${GREEN?}'Creating Cloud SQL database for Hydra.'${RESET?}

gcloud sql instances create hydra --project=${PROJECT?} --database-version=POSTGRES_11 \
  --tier=db-f1-micro --zone=us-central1-a --require-ssl
# Create user: name="${NAME}", password="${PASSWORD}"
gcloud sql users create ${DB_USER?} --project=${PROJECT?} --instance=hydra --password=${DB_PASSWORD?}
# Create database ic
gcloud sql databases create ic --project=${PROJECT?} --instance=hydra

echo -e ${GREEN?}'Complete.'${RESET?}

echo -e ${YELLOW?}'1. Enable private ip connect for database in Connectivity tab https://console.cloud.google.com/sql/instances/hydra/edit-performance-class?project=${PROJECT?}'
echo -e '2. run `./import.bash -p '${PROJECT?}' ic` to init datastore'
echo -e ${RESET?}
