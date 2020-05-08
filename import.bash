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

# Import IC and DAM service data storage (i.e. wipe existing config)
# Usage:
#   ./import.bash [<flags>] [dam | ic]

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

PROJECT=${PROJECT}
ENV=""
IMPORT_TYPE=""

print_usage() {
  echo -e ${RED?}'Usage: import [-e environment] [-h] [-p project_id] [-P config_path] [-t config | permissions | secrets | all] [dam | ic] ...'${RESET?}
  echo -e ${RED?}'  -e \t extra environment namespace to include in the deployed service name'${RESET?}
  echo -e ${RED?}'     \t example: "import -e staging dam ic" will import services "dam-staging", "ic-staging"'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
  echo -e ${RED?}'  -t \t import config, permission, security or all'${RESET?}
  echo
  echo -e ${RED?}'  all flags must be provided before service names'${RESET?}
}

while getopts ':he:p:t:' flag; do
  case "${flag}" in
    e) ENV="${OPTARG}" ;;
    h) print_usage
       exit 1 ;;
    p) PROJECT="${OPTARG}" ;;
    t) IMPORT_TYPE="${OPTARG}" ;;
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

ENV_LABEL=${ENV?}
if [[ "${ENV?}" == "" ]]; then
  ENV_LABEL="DEFAULT"
fi

if [[ "${IMPORT_TYPE?}" == "" ]]; then
  echo -e ${RED?}'Must provide a config type via or -t config | permissions | secrets | all'${RESET?}
  print_usage
  exit 1
fi

MATCH=false
IC=false
DAM=false
ARGS=("$@")
for arg in "${ARGS[@]}"; do
  if [[ $arg == "ic" ]]; then
    IC=true
    MATCH=true
  elif [[ $arg == "dam" ]]; then
    DAM=true
    MATCH=true
  fi
done

if [ "$MATCH" == false ] ; then
  IC=true
  DAM=true
fi

if [ "$DAM" == true ] ; then
  echo "IMPORT: DAM configs (${ENV_LABEL?}) in project ${PROJECT?}"
  $(go run "gcp/dam_import/main.go" "${PROJECT?}" "${ENV?}" "${IMPORT_TYPE?}" >/dev/null)
  STATUS=$?
  if [ "$STATUS" == 0 ]; then
    echo -e "${GREEN?}Import DAM configs succeeded${RESET?}"
  else
    echo -e "${RED?}Import DAM configs failed${RESET?}"
    exit $STATUS
  fi
fi
if [ "$IC" == true ] ; then
  echo "IMPORT: IC configs (${ENV_LABEL?}) in project ${PROJECT?}"
  $(go run "gcp/ic_import/main.go" "${PROJECT?}" "${ENV?}" "${IMPORT_TYPE?}" >/dev/null)
  STATUS=$?
  if [ "$STATUS" == 0 ]; then
    echo -e "${GREEN?}Import IC succeeded${RESET?}"
  else
    echo -e "${RED?}Import IC failed${RESET?}"
    exit $STATUS
  fi
fi
