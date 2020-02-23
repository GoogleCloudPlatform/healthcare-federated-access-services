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
unset CONFIG_ONLY

print_usage() {
  echo -e ${RED?}'Usage: deploy [-c] [-b] [-e environment] [-f] [-h] [-i] [-p project_id] [service_name service_name ...]'${RESET?}
  echo -e ${RED?}'  -b \t bypass build of services'${RESET?}
  echo -e ${RED?}'  -c \t config generation only'${RESET?}
  echo -e ${RED?}'  -e \t extra environment namespace to include in the deployed service name'${RESET?}
  echo -e ${RED?}'     \t example: "deploy -e staging dam ic" will deploy services as "dam-staging", "ic-staging"'${RESET?}
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
  if [[ "${SKIP_ARG}" != "" ]]; then
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

while getopts ':bce:hip:' flag; do
  case "${flag}" in
    b) BYPASS_BUILD='true' ;;
    c) CONFIG_ONLY='true' ;;
    e) ENV="-${OPTARG}" ;;
    h) print_usage
       exit 1 ;;
    i) PROMPT='true' ;;
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

# Generate the config files
if [[ "${IC_CONFIG}" == "" ]]; then
  echo -e ${GREEN?}'Generating the default IC config files.'${RESET?}
  echo -e ${GREEN?}'To use your own configs instead, set environment variable "IC_CONFIG" to point to your config folders.'${RESET?}
else
  echo -e ${GREEN?}'Using the provided IC_CONFIG files at: '${IC_CONFIG?}${RESET?}
fi
if [[ "${DAM_CONFIG}" == "" ]]; then
  echo -e ${GREEN?}'Generating the default DAM config files.'${RESET?}
  echo -e ${GREEN?}'To use your own configs instead, set environment variable "DAM_CONFIG" to point to your config folders.'${RESET?}
else
  echo -e ${GREEN?}'Using the provided DAM_CONFIG file at: '${DAM_CONFIG?}${RESET?}
fi
if [[ "$PROMPT" != "" ]]; then
  echo -e ${GREEN?}'PRESS ENTER TO CONTINUE...'${RESET?}
  read
fi

# Create IC and DAM config directories if they do not exist.
mkdir -p ./deploy/config/ic/
mkdir -p ./deploy/config/dam/

if [[ "${IC_CONFIG}" == "" ]]; then
  cp -R ./deploy/config/ic-template/* ./deploy/config/ic/
else
  cp -R $IC_CONFIG/* ./deploy/config/ic/
fi

if [[ "${DAM_CONFIG}" == "" ]]; then
  cp -R ./deploy/config/dam-template/* ./deploy/config/dam/
else
  cp -R $DAM_CONFIG/* ./deploy/config/dam/
fi

sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/config_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/ic/config_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/secrets_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/ic/secrets_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/dam/config_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/dam/config_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/dam/secrets_master_main_latest.json
sed -i 's/${YOUR_ENVIRONMENT}/'${ENV?}'/g' ./deploy/config/dam/secrets_master_main_latest.json

mkdir -p ./deploy/build/
cp -R  ./deploy/build-templates/* ./deploy/build/

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

if [[ "${CONFIG_ONLY}" != "" ]]; then
  echo -e ${GREEN?}'CONFIG_ONLY flag is set. Skipping all other steps.'${RESET?}
  exit 0
fi

# Build the Personas, IC, ICDEMO, DAM, and DAMDEMO images
if [[ "${BYPASS_BUILD}" == "" ]]; then
  echo -e ${GREEN?}'Building Docker images for the services.'${RESET?}
  if [[ "$PROMPT" != "" ]]; then
    echo -e ${GREEN?}'PRESS ENTER TO CONTINUE...'${RESET?}
    read
  fi

  if deploy_service "personas" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building Personas Docker Image.'${RESET?}
    gcloud builds submit --project=${PROJECT?} --config deploy/build/personas/cloudbuild.yaml .
  fi

  if deploy_service "ic" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building IC Docker Image.'${RESET?}
    gcloud builds submit --project=${PROJECT?} --config deploy/build/ic/cloudbuild.yaml .
  fi

  if deploy_service "icdemo" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building ICDEMO Docker Image.'${RESET?}
    gcloud builds submit --project=${PROJECT?} --config deploy/build/icdemo/cloudbuild.yaml .
  fi

  if deploy_service "dam" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building DAM Docker Image.'${RESET?}
    gcloud builds submit --project=${PROJECT?} --config deploy/build/dam/cloudbuild.yaml .
  fi

  if deploy_service "damdemo" $BYPASS_BUILD; then
    echo -e ${GREEN?}'Building DAMDEMO Docker Image.'${RESET?}
    gcloud builds submit --project=${PROJECT?} --config deploy/build/damdemo/cloudbuild.yaml .
  fi
else
  echo -e ${GREEN?}'BYPASS_BUILD flag is set. Bypassing the building of Docker images for the services.'${RESET?}
fi

# Deploy Services
echo -e ${GREEN?}'Deploying services to the GCP project.'${RESET?}
if [[ "${PROMPT}" != "" ]]; then
  echo -e ${GREEN?}'PRESS ENTER TO CONTINUE...'${RESET?}
  read
fi

if deploy_service "personas"; then
  echo -e ${GREEN?}'Deploy PERSONA BROKER.'${RESET?}
  gcloud beta -q --project=${PROJECT?} app deploy deploy/build/personas/personas.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-personas:latest --version=latest
fi

if deploy_service "ic"; then
  echo -e ${GREEN?}'Deploy IC.'${RESET?}
  gcloud beta -q --project=${PROJECT?} app deploy deploy/build/ic/ic.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-ic:latest --version=latest
fi

if deploy_service "icdemo"; then
  echo -e ${GREEN?}'Deploy ICDEMO.'${RESET?}
  gcloud beta -q --project=${PROJECT?} app deploy deploy/build/icdemo/icdemo.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-icdemo:latest --version=latest
fi

if deploy_service "dam"; then
  echo -e ${GREEN?}'Deploy DAM.'${RESET?}
  gcloud beta -q --project=${PROJECT?} app deploy deploy/build/dam/dam.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-dam:latest --version=latest
fi

if deploy_service "damdemo"; then
  echo -e ${GREEN?}'Deploy DAMDEMO.'${RESET?}
  gcloud beta -q --project=${PROJECT?} app deploy deploy/build/damdemo/damdemo.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-damdemo:latest --version=latest
fi

echo -e ${GREEN?}'=== DEPLOY COMPLETE ==='${RESET?}
