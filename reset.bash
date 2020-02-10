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

# Reset IC and DAM service data storage (i.e. wipe database)
# Usage:
#   ./reset.bash [<flags>] [dam | ic]

GREEN="\e[32m"
RED="\e[31m"
RESET="\e[0m"

PROJECT=${PROJECT}
ENV_LABEL=""

print_usage() {
  echo -e ${RED?}'Usage: reset [-e environment] [-h] [-p project_id] [-P config_path] [dam | ic] ...'${RESET?}
  echo -e ${RED?}'  -e \t extra environment namespace to include in the deployed service name'${RESET?}
  echo -e ${RED?}'     \t example: "reset -e staging dam ic" will reset services "dam-staging", "ic-staging"'${RESET?}
  echo -e ${RED?}'  -h \t show this help usage'${RESET?}
  echo -e ${RED?}'  -p \t GCP project_id to deploy to'${RESET?}
  echo
  echo -e ${RED?}'  all flags must be provided before service names'${RESET?}
}

while getopts ':he:p:' flag; do
  case "${flag}" in
    e) ENV_LABEL="${OPTARG}" ;;
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

ENV=""
if [[ "${ENV_LABEL}" == "" ]]; then
  ENV_LABEL="DEFAULT"
else
  ENV="-${ENV_LABEL}"
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
  echo "RESET DAM (${ENV_LABEL?}) in project ${PROJECT?}"
  $(go run "gcp/dam_reset/main.go" "${PROJECT?}" "dam${ENV?}" "deploy/config" "ic${ENV?}-" >/dev/null)
  STATUS=$?
  if [ "$STATUS" == 0 ]; then
    echo -e "${GREEN?}Reset DAM succeeded${RESET?}"
  else
    echo -e "${RED?}Reset DAM failed${RESET?}"
    exit $STATUS
  fi
fi
if [ "$IC" == true ] ; then
  echo "RESET IC (${ENV_LABEL?}) in project ${PROJECT?}"
  $(go run "gcp/ic_reset/main.go" "${PROJECT?}" "ic${ENV?}" >/dev/null)
  STATUS=$?
  if [ "$STATUS" == 0 ]; then
    echo -e "${GREEN?}Reset IC succeeded${RESET?}"
  else
    echo -e "${RED?}Reset IC failed${RESET?}"
    exit $STATUS
  fi
fi
