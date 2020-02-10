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

# TODO: initial steps

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

PROJECT=${PROJECT}
# Service names have "_" prefix and suffix to allow full service name matching
# using a substring search on the merged list.
SERVICE_NAMES=("_ic_" "_dam_" "_personas_" "_icdemo_" "_damdemo_")
ENV=""
unset PROMPT
unset BYPASS_BUILD
unset FAST_DEPLOY
unset CONFIG_ONLY

print_usage() {
  echo -e ${RED?}'Usage: deploy [-c] [-b] [-e environment] [-f] [-h] [-i] [-p project_id] [service_name service_name ...]'${RESET?}
  echo -e ${RED?}'  -b \t bypass build of services'${RESET?}
  echo -e ${RED?}'  -c \t config generation only'${RESET?}
  echo -e ${RED?}'  -e \t extra environment namespace to include in the deployed service name'${RESET?}
  echo -e ${RED?}'     \t example: "deploy -e staging dam ic" will deploy services as "dam-staging", "ic-staging"'${RESET?}
  echo -e ${RED?}'  -f \t fast deploy will skip project initialization and service dependency setup'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -i \t interactive prompts to proceed between steps'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
  echo
  echo -e ${RED?}'  service names: '"${SERVICE_NAMES[@]//_}"${RESET?}
  echo
  echo -e ${RED?}'  all flags must be provided before service names'${RESET?}
}

echo -e ${GREEN?}'Args: '"$@"${RESET?}

ARGS=("$@")
DEPLOY=()
unset SKIP_ARG
for arg in "${ARGS[@]}"; do
  if [[ -v SKIP_ARG ]]; then
    # previous was a flag and this is that flag's string argument
    unset SKIP_ARG
  elif [[ $arg == -* ]]; then
    # arg is a flag
    if [[ "${#DEPLOY[@]}" != "0" ]]; then
      echo -e ${RED?}'Flag "'$arg'" must be specified before any service names'${RESET?}
      exit 1
    elif [[ "$arg" == "-e" || "$arg" == "-p" ]]; then
      SKIP_ARG='true'
    fi
  elif [[ "${SERVICE_NAMES[@]}" =~ '_'$arg'_' ]]; then
    DEPLOY+=('_'$arg'_')
  else
    echo -e ${RED?}'Service "'$arg'" is not a valid service name'${RESET?}
    exit 1
  fi
done
if [[ "${#DEPLOY[@]}" == "0" ]]; then
  # When no services are specified to deploy, then deploy all of them.
  DEPLOY=("${SERVICE_NAMES[@]}")
fi

while getopts ':bce:fhip:' flag; do
  case "${flag}" in
    b) BYPASS_BUILD='true' ;;
    c) CONFIG_ONLY='true' ;;
    e) ENV="-${OPTARG}" ;;
    f) FAST_DEPLOY='true' ;;
    h) print_usage
       exit 1 ;;
    i) PROMPT='true' ;;
    p) PROJECT="${OPTARG}" ;;
    *) echo -e ${RED?}'Unknown flag: -'${flag}${RESET?}
       print_usage
       exit 1 ;;
  esac
done

if [[ -z "${PROJECT}" ]]; then
  echo -e ${RED?}'Must provide a project via $PROJECT or -p project'${RESET?}
  print_usage
  exit 1
fi

deploy_service() {
  if [[ "${DEPLOY[@]}" =~ "_$1_" && -z $2 ]]; then
    return
  fi
  echo -e ${GREEN?}'SKIP service "'$1'"'${RESET?}
  false
}

# You need to loging to gcloud and createa a project using gcloud cli.
# Export the id of your project to environment variable PROJECT.
echo -e ${GREEN?}'Starting deployment to project: '${PROJECT?}${RESET?}
gcloud config set project ${PROJECT?}
export PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")

# Generate the config files
if [[ -v IC_CONFIG ]]; then
  echo -e ${GREEN?}'Using the provided IC_CONFIG files at: '${IC_CONFIG?}${RESET?}
else
  echo -e ${GREEN?}'Generating the default IC config files.'${RESET?}
  echo -e ${GREEN?}'To use your own configs instead, set environment variable "IC_CONFIG" to point to your config folders.'${RESET?}
fi
if [[ -v DAM_CONFIG ]]; then
  echo -e ${GREEN?}'Using the provided DAM_CONFIG file at: '${DAM_CONFIG?}${RESET?}
else
  echo -e ${GREEN?}'Generating the default DAM config files.'${RESET?}
  echo -e ${GREEN?}'To use your own configs instead, set environment variable "DAM_CONFIG" to point to your config folders.'${RESET?}
fi
if [[ -v PROMPT ]]; then
  echo -e ${GREEN?}'PRESS ENTER TO CONTINUE...'${RESET?}
  read
fi

# Create IC and DAM config directories if they do not exist.
mkdir -p ./deploy/config/ic/
mkdir -p ./deploy/config/dam/

if [ -v IC_CONFIG ]; then
  cp -R $IC_CONFIG/* ./deploy/config/ic/
else
  cp -R ./deploy/config/ic-template/* ./deploy/config/ic/
fi

if [ -v DAM_CONFIG ]; then
  cp -R $DAM_CONFIG/* ./deploy/config/dam/
else
  cp -R ./deploy/config/dam-template/* ./deploy/config/dam/
fi

sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/config_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/ic/config_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/secrets_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/ic/secrets_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/dam/config_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/dam/config_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/dam/secrets_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/dam/secrets_master_main_latest.json

sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/personas/Dockerfile
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/hydra/Dockerfile
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/ic/Dockerfile
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/icdemo/Dockerfile
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/dam/Dockerfile
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/damdemo/Dockerfile

sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/personas/personas.yaml
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/ic/ic.yaml
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/icdemo/icdemo.yaml
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/dam/dam.yaml
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/build/damdemo/damdemo.yaml

sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/build/personas/personas.yaml
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/build/ic/ic.yaml
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/build/icdemo/icdemo.yaml
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/build/dam/dam.yaml
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/build/damdemo/damdemo.yaml

if [[ -v CONFIG_ONLY ]]; then
  echo -e ${GREEN?}'CONFIG_ONLY flag is set. Skipping all other steps.'${RESET?}
  exit 0
fi

if [[ -v FAST_DEPLOY ]]; then
  echo -e ${GREEN?}'FAST_DEPLOY flag is set. Skipping preparing the GCP project for deployment.'${RESET?}
else
  echo -e ${GREEN?}'Preparing the GCP project for deployment. To skip, set "FAST_DEPLOY" flag -f.'${RESET?}
  # Enbable the required APIs.
  echo -e ${GREEN?}'Enabling the required APIs.'${RESET?}

  gcloud services enable \
    appengine.googleapis.com \
    appengineflex.googleapis.com \
    appenginestandard.googleapis.com \
    sql-component.googleapis.com \
    sqladmin.googleapis.com \
    datastore.googleapis.com \
    iam.googleapis.com \
    cloudbuild.googleapis.com \
    bigquery.googleapis.com \
    storage-component.googleapis.com \
    cloudkms.googleapis.com

  # Create a GAE app.
  gcloud app create --region=us-central

  # Grant the required permissions.
  echo -e ${GREEN?}'Granting the required permissions.'${RESET?}

  gcloud projects add-iam-policy-binding -q ${PROJECT?} \
    --member serviceAccount:${PROJECT?}@appspot.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
  gcloud projects add-iam-policy-binding -q ${PROJECT?} \
    --member serviceAccount:${PROJECT?}@appspot.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator

  gcloud projects add-iam-policy-binding -q ${PROJECT?} \
    --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudsql.client
  gcloud projects add-iam-policy-binding -q ${PROJECT?} \
    --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/editor
  gcloud projects add-iam-policy-binding -q ${PROJECT?} \
    --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/resourcemanager.projectIamAdmin

  # TODO: make region configurable.

  # Setup Cloud SQL
  # Create a CloudSQL db-f1-micro (memory=128M, disk=250G) postgres 11 instance in us-central-1.
  echo -e ${GREEN?}'Creating Cloud SQL database for Hydra.'${RESET?}

  gcloud sql instances create hydra --database-version=POSTGRES_11 \
    --tier=db-f1-micro --region=us-central1
  # Create user: name="${NAME}", password="${PASSWORD}"
  gcloud sql users create hydra --instance=hydra --password=hydra
  # Create database ic
  gcloud sql databases create ic --instance=hydra
  # Create database dam
  gcloud sql databases create dam --instance=hydra

  echo -e ${GREEN?}'Creating a GCS bucket with an example file.'${RESET?}

  gsutil mb gs://${PROJECT?}-test-dataset
  tempdir=`mktemp -d`
  pushd $tempdir
  echo "This is an example" > example.txt
  gsutil cp example.txt gs://${PROJECT?}-test-dataset
  popd
  rm -rf $tempdir

  # Deploy a simple defaut app to GAE default service.
  echo -e ${GREEN?}'Deploy a helloworld to GAE default service.'${RESET?}

  tempdir=`mktemp -d`
  pushd $tempdir
  git clone https://github.com/GoogleCloudPlatform/golang-samples.git
  pushd golang-samples/appengine/go11x/helloworld
  gcloud -q app deploy .
  popd
  popd
  rm -rf $tempdir

  echo -e ${GREEN?}'Building Base Hydra Docker Image.'${RESET?}
  gcloud builds submit --config deploy/build/hydra/cloudbuild.yaml .
fi

# Build the Personas, IC, ICDEMO, DAM, and DAMDEMO images
if [[ -v BYPASS_BUILD ]]; then
  echo -e ${GREEN?}'BYPASS_BUILD flag is set. Bypassing the building of Docker images for the services.'${RESET?}
else
  echo -e ${GREEN?}'Building Docker images for the services.'${RESET?}
  if [[ -v PROMPT ]]; then
    echo -e ${GREEN?}'PRESS ENTER TO CONTINUE...'${RESET?}
    read
  fi

  if deploy_service "personas" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building Personas Docker Image.'${RESET?}
    gcloud builds submit --config deploy/build/personas/cloudbuild.yaml .
  fi

  if deploy_service "ic" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building IC Docker Image.'${RESET?}
    gcloud builds submit --config deploy/build/ic/cloudbuild.yaml .
  fi

  if deploy_service "icdemo" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building ICDEMO Docker Image.'${RESET?}
    gcloud builds submit --config deploy/build/icdemo/cloudbuild.yaml .
  fi

  if deploy_service "dam" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building DAM Docker Image.'${RESET?}
    gcloud builds submit --config deploy/build/dam/cloudbuild.yaml .
  fi

  if deploy_service "damdemo" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building DAMDEMO Docker Image.'${RESET?}
    gcloud builds submit --config deploy/build/damdemo/cloudbuild.yaml .
  fi
fi

# Deploy Services
echo -e ${GREEN?}'Deploying services to the GCP project.'${RESET?}
if [[ -v PROMPT ]]; then
  echo -e ${GREEN?}'PRESS ENTER TO CONTINUE...'${RESET?}
  read
fi

if deploy_service "personas"; then
  echo -e ${GREEN?}'Deploy PERSONA BROKER.'${RESET?}
  gcloud beta -q app deploy deploy/build/personas/personas.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-personas:latest
fi

if deploy_service "ic"; then
  echo -e ${GREEN?}'Deploy IC.'${RESET?}
  gcloud beta -q app deploy deploy/build/ic/ic.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-ic:latest
fi

if deploy_service "icdemo"; then
  echo -e ${GREEN?}'Deploy ICDEMO.'${RESET?}
  gcloud beta -q app deploy deploy/build/icdemo/icdemo.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-icdemo:latest
fi

if deploy_service "dam"; then
  echo -e ${GREEN?}'Deploy DAM.'${RESET?}
  gcloud beta -q app deploy deploy/build/dam/dam.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-dam:latest
fi

if deploy_service "damdemo"; then
  echo -e ${GREEN?}'Deploy DAMDEMO.'${RESET?}
  gcloud beta -q app deploy deploy/build/damdemo/damdemo.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-damdemo:latest
fi

echo -e ${GREEN?}'=== DEPLOY COMPLETE ==='${RESET?}
