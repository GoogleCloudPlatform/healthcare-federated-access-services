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
RESET="\e[0m"

IC_CLIENT_ID="903cfaeb-57d9-4ef6-5659-04377794ed65"
IC_CLIENT_SECRET="48f7e552-d9b7-42f3-ba76-e5ab5b3c70ab"
DAM_CLIENT_ID="903cfaeb-57d9-4ef6-5659-04377794ed65"
DAM_CLIENT_SECRET="48f7e552-d9b7-42f3-ba76-e5ab5b3c70ab"

STATE_FILE=~/.fa_admin
API_VERSION="v1alpha"
REALM="master"

# For curl debug use:
# CURL_OPTIONS="-v --trace-ascii /dev/stdout -s"
CURL_OPTIONS="-s"

# Commands are added here and usage is auto-generated. Note that user supplied
# args can be supplied (e.g. "<name>") starting on the 4th input and must then
# be on every second input. Avoid conflicts with arg commands and non-arg
# commands by pretending all <named_arg> fields are removed and seeing if there
# is a collision. Example: "print hello" and "print hello <name>" collide.
#
# Most service endpoint commands will make one of three types of calls:
# 1. curl_public <dam|ic> <resource_path>: when anyone can hit the endpoint.
# 2. <dam_curl_client|ic_curl_client> <resource_path>: when client_id and
#    client_secret are needed to identify the application.
# 3. <dam_curl_auth|ic_curl_auth> <resource_path>: when client id/secret and
#    an access_token are required to identify the app and the user.
declare -A COMMANDS=(
  # DAM commands
  ["print dam config"]='dam_curl_auth "/dam/${API_VERSION?}/${REALM?}/config"'
  ["print ic config history"]='dam_curl_auth "/dam/${API_VERSION?}/${REALM?}/config/history"'
  ["print dam info"]='curl_public "dam" "/dam"'
  ["print dam processes"]='dam_curl_auth "/dam/${API_VERSION?}/${REALM?}/processes"'
  ["print dam process <name>"]='dam_curl_auth "/dam/${API_VERSION?}/${REALM?}/processes/$4"'
  ["print dam resource <name>"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/resources/$4"'
  ["print dam resource <name> views"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/resources/$4/views"'
  ["print dam resource <name> view <name>"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/resources/$4/views/$6"'
  ["print dam resource <name> view <name> roles"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/resources/$4/views/$6/roles"'
  ["print dam resource <name> view <name> role <name>"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/resources/$4/views/$6/roles"'
  ["print dam resources"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/resources"'
  ["print dam adapters"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/targetAdapters"'
  ["print dam personas"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/testPersonas"'
  ["print dam roles"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/damRoleCategories"'
  ["print dam translators"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/passportTranslators"'
  ["print dam views"]='dam_curl_client "/dam/${API_VERSION?}/${REALM?}/flatViews"'
  ["sync dam config clients"]='dam_curl_auth "/dam/${API_VERSION?}/${REALM?}/config/clients:sync"'
  # IC commands
  ["print ic config"]='ic_curl_auth "/identity/${API_VERSION?}/${REALM?}/config"'
  ["print ic config history"]='ic_curl_auth "/identity/${API_VERSION?}/${REALM?}/config/history"'
  ["print ic idps"]='ic_curl_client "/identity/${API_VERSION?}/${REALM?}/identityProviders"'
  ["print ic info"]='curl_public "ic" "/identity"'
  ["print ic me"]='ic_curl_auth "/identity/scim/v2/${REALM?}/Me"'
  ["print ic translators"]='ic_curl_client "/identity/${API_VERSION?}/${REALM?}/passportTranslators"'
  ["print ic user <name>"]='ic_curl_auth "/identity/scim/v2/${REALM?}/Users/$4"'
  ["print ic users"]='ic_curl_auth "/identity/scim/v2/${REALM?}/Users"'
  ["sync ic config clients"]='ic_curl_auth "/identity/${API_VERSION?}/${REALM?}/config/clients:sync"'
  # Admin state commands
  ["set state dam access_token <token>"]='state_update "DAM_ACCESS_TOKEN" "$5"'
  ["set state dam client <client_id>"]='state_update "DAM_CLIENT_ID" "$5"'
  ["set state dam secret <secret>"]='state_update "DAM_CLIENT_SECRET" "$5"'
  ["set state env <environment>"]='state_update "ENVIRONMENT" "$4"'
  ["set state ic access_token <token>"]='state_update "IC_ACCESS_TOKEN" "$5"'
  ["set state ic client <client_id>"]='state_update "IC_CLIENT_ID" "$5"'
  ["set state ic secret <secret>"]='state_update "IC_CLIENT_SECRET" "$5"'
  ["set state project <project_id>"]='state_update "PROJECT" "$4"'
  ["set state realm <realm>"]='state_update "REALM" "$4"'
  ["print state"]='state_print'
  ["reset state"]='state_reset'
)

# Only commands on this list are allowed in the COMMANDS list above.
declare -A COMMAND_WHITELIST=(
  ["curl_public"]=true
  ["dam_curl_auth"]=true
  ["dam_curl_client"]=true
  ["ic_curl_auth"]=true
  ["ic_curl_client"]=true
  ["state_print"]=true
  ["state_reset"]=true
  ["state_update"]=true
)

#####################################################
# State helper functions                            #
#####################################################

# Sets variable $1 to value $2 and saves it to disk to be retrieved on
# subsequent runs.
state_update() {
  if [[ "$1" == "" || "$2" == "" ]]; then
    print_usage
    exit 1
  fi
  export "$1"="$2"
  state_save
}

# Loads a set of variables (i.e. state) from disk. See the "set state" commands
# for a list of such variables.
state_load() {
  if test -f "${STATE_FILE?}"; then
    local settings=`cat "${STATE_FILE?}"`
    local settings=(${settings/$'\n'/ })
    # Don't blindly eval() something we loaded from elsewhere. Instead, process
    # one line at a time and verify of the form of A=B with explicit "export"
    # command for context within this script.
    for setting in "${settings[@]}"; do
      local parts=(${setting//=/ })
      NAME="${parts[0]}"
      VALUE="${parts[1]}"
      if [[ "${NAME}" == "" ]]; then
        echo -e ${RED?}'invalid state "'"${setting}"'": recommend running "admin state reset"'${RESET?}
        exit 2
      fi
      # This check prevents injecting commands into this script by ensuring
      # that input is simple identifier characters and doesn't a means to
      # manipulate/escape string quote state, etc.
      if grep '^[-0-9a-zA-Z_.=]*$' <<<${setting} > /dev/null; then
        export "$NAME"="$VALUE"
      else
        echo -e "${RED?}invalid characters in state \"${setting}\": recommend running \"admin state reset\"${RESET?}"
        exit 2
      fi
    done
  fi
}

# Generates the contents of the state as a string to be saved or printed.
state_string() {
  STATE_STRING="PROJECT=${PROJECT}\nENVIRONMENT=${ENVIRONMENT}\nREALM=${REALM}\nDAM_CLIENT_ID=${DAM_CLIENT_ID}\nDAM_CLIENT_SECRET=${DAM_CLIENT_SECRET}\nIC_CLIENT_ID=${IC_CLIENT_ID}\nIC_CLIENT_SECRET=${IC_CLIENT_SECRET}\nDAM_ACCESS_TOKEN=${DAM_ACCESS_TOKEN}\nIC_ACCESS_TOKEN=${IC_ACCESS_TOKEN}\n"
}

# Generate all state as a string and print it.
state_print() {
  state_string
  printf "${STATE_STRING}"
}

# Generate all state and a string and save it to disk.
state_save() {
  state_string
  printf "${STATE_STRING}" >"${STATE_FILE?}"
  echo -e ${GREEN?}'state updated'${RESET?}
}

# Remove the state file from disk. Will inherit default state values on the
# next run.
state_reset() {
  rm "${STATE_FILE?}" > /dev/null 2>&1
  echo -e ${GREEN?}'state reset complete'${RESET?}
}

#####################################################
# Curl helper functions                             #
#####################################################

# curl_public <dam|ic> <resource_path>
# Generates a URL then performs a GET using curl as part of a RESTful API.
curl_public() {
  if [[ "$2" == "" ]]; then
    echo -e "${RED?}must provide RESTful path to resource${RESET?}"
    exit 2
  fi
  local dash="-"
  if [[ "${ENVIRONMENT}" == "" ]]; then
    dash=""
  fi
  RESULT=`curl -s "$1${dash}${ENVIRONMENT}-dot-${PROJECT}.appspot.com$2"`
  # Check to see if result is JSON, then pretty print in JSON if available.
  `jq -e <<< "${RESULT}" > /dev/null 2>&1`
  if [[ "$?" == "0" ]]; then
    printf "`jq -e <<< "${RESULT}"`"
  else
    echo "${RESULT}"
  fi
  echo
}

# curl_client <dam|ic> <resource_path> <client_id> <client_secret>
# Generates a URL then performs a GET using curl as part of a RESTful API.
# Unlike curl_public, this function adds the client id/secret to the request.
curl_client() {
  if [[ "$4" == "" ]]; then
    echo -e "${RED?}client id and secret required: use \"admin set state $1 secret <paste_secret>\" etc${RESET?}"
    exit 2
  fi
  local dash="-"
  if [[ "${ENVIRONMENT}" == "" ]]; then
    dash=""
  fi
  RESULT=`curl ${CURL_OPTIONS} -X "GET" -H "Content-Type: application/x-www-form-urlencoded" "$1${dash}${ENVIRONMENT}-dot-${PROJECT}.appspot.com$2?client_id=$3&client_secret=$4"`
  # Check to see if result is JSON, then pretty print in JSON if available.
  `jq -e <<< "${RESULT}" > /dev/null 2>&1`
  if [[ "$?" == "0" ]]; then
    printf "`jq -e <<< "${RESULT}"`"
  else
    echo "${RESULT}"
  fi
  echo
}

# curl_auth <dam|ic> <resource_path> <client_id> <client_secret> <access_token>
# Generates a URL then performs a GET using curl as part of a RESTful API.
# Unlike curl_public, this function adds the auth headers and client id/secret
# to the request.
curl_auth() {
  if [[ "$5" == "" ]]; then
    echo -e "${RED?}login access_token required: use \"admin set state $1 access_token <paste_token>\"${RESET?}"
    exit 2
  fi
  local dash="-"
  if [[ "${ENVIRONMENT}" == "" ]]; then
    dash=""
  fi
  RESULT=`curl ${CURL_OPTIONS} -X "GET" -H "Authorization: bearer $5" -H "Content-Type: application/x-www-form-urlencoded" "$1${dash}${ENVIRONMENT}-dot-${PROJECT}.appspot.com$2?client_id=$3&client_secret=$4"`
  # Check to see if result is JSON, then pretty print in JSON if available.
  `jq -e <<< "${RESULT}" > /dev/null 2>&1`
  if [[ "$?" == "0" ]]; then
    printf "`jq -e <<< "${RESULT}"`"
  else
    echo "${RESULT}"
  fi
  echo
}

# dam_curl_auth <resource_path>
# Wrapper for curl_auth that supplies a set of DAM inputs for client id/secret
# and access token that were loaded from disk. Makes it easier to write COMMANDS
# by abstracting all of these details.
dam_curl_auth() {
  curl_auth "dam" "$1" "${DAM_CLIENT_ID}" "${DAM_CLIENT_SECRET}" "${DAM_ACCESS_TOKEN}"
}

# dam_curl_client <resource_path>
# Wrapper for curl_client that supplies a set of DAM inputs for client id/secret.
dam_curl_client() {
  curl_client "dam" "$1" "${DAM_CLIENT_ID}" "${DAM_CLIENT_SECRET}"
}

# ic_curl_auth <resource_path>
# Wrapper for curl_auth that supplies a set of IC inputs for client id/secret
# and access token that were loaded from disk. Makes it easier to write COMMANDS
# by abstracting all of these details.
ic_curl_auth() {
  curl_auth "ic" "$1" "${IC_CLIENT_ID}" "${IC_CLIENT_SECRET}" "${IC_ACCESS_TOKEN}"
}

# ic_curl_client <resource_path>
# Wrapper for curl_client that supplies a set of IC inputs for client id/secret.
ic_curl_client() {
  curl_client "ic" "$1" "${IC_CLIENT_ID}" "${IC_CLIENT_SECRET}"
}

#####################################################
# Generate COMMAND_LOOKUP and Usage                 #
#####################################################

# Generates the usage from COMMANDS and prints them.
print_usage() {
  echo -e ${RED?}'Usage: admin <command>'${RESET?}
  echo -e ${RED?}'  commands:'${RESET?}

  for cmd in "${!COMMANDS[@]}"; do
    echo -e "${RED?}    ${cmd}${RESET?}"
  done | sort

  echo
  echo -e "${RED?}Note: some commands are only available in experimental mode${RESET?}"
  echo
}

# Removes any input parameters from COMMANDS usage key. This is used to generate
# a lookup table of commands and match incoming commands with parameters like
# "<name>".
remove_key_params() {
  words=( $1 )
  keys=()
  for word in "${words[@]}"; do
    if [[ "${word:0:1}" != "<" ]]; then
      keys+=( "${word}" )
    fi
  done
  keys=$(printf " %s" ${keys[@]})
  LOOKUP_KEY=${keys:1}
}

# Generates COMMAND_LOOKUP from COMMANDS by removing input parameters.
declare -A COMMAND_LOOKUP
for cmd in "${!COMMANDS[@]}"; do
  remove_key_params "$cmd"
  COMMAND_LOOKUP["${LOOKUP_KEY?}"]="${COMMANDS[${cmd}]}"
done

#####################################################
# Command Execution                                 #
#####################################################

# Executes a command by expanding the input parameters from $1.
run_command() {
  echo -e "${GREEN?}${PROJECT?} ${ENVIRONMENT?} ${REALM?}${RESET?}"
  # Manually replace variables without eval() and strip quotes from args.
  local line=$1
  local re='(.*)(\$\{([^\}]+)\})(.*)'
  while [[ $line =~ $re ]]; do
    varname=${BASH_REMATCH[3]/\?/}
    line="${BASH_REMATCH[1]}${!varname}${BASH_REMATCH[4]}"
  done
  args=()
  declare -a "array=( $(echo ${line} | tr '`$<>' '????') )"
  for arg in "${array[@]}"; do
    arg=${arg/\"/}
    arg=${arg/\"/}
    args+=( $arg )
  done

  # Check whitelist to see if this command is authorized to limit risk from
  # variables injecting bad stuff.
  if [[ "${COMMAND_WHITELIST[${args[0]}]}" == "" ]]; then
    echo -e "${RED?}command \"${cmd}\" is not whitelisted and therefore this command is unauthorized${RESET?}"
    exit 2
  fi

  # Execute the whitelisted command with parameters.
  ${args[@]}
  if [[ "$?" == "0" ]]; then
    echo -e "${GREEN?}done${RESET?}"
  else
    echo -e "${RED?}command failed${RESET?}"
  fi
  echo
  exit $?
}

# Prepare for processing input.
state_load

# Lookup the command from COMMANDS, but adjust for the last input being a
# variable if the first word in the command is "set".
lookup="$@"
words=( $lookup )
if [[ "${words[0]}" == "set" ]]; then
  words[-1]=""
  lookup=$(printf " %s" ${words[@]})
  lookup=${lookup:1}
fi

# Now we have the lookup string for commands in COMMAND_LOOKUP, so find what to
# execute ("exec") and if it is empty, there is no such command.
exec="${COMMAND_LOOKUP[$lookup]}"
if [[ "${exec}" != "" ]]; then
  # Do substitutions here before the function call changes the args.
  exec=${exec/\$3/$3}
  exec=${exec/\$4/$4}
  exec=${exec/\$5/$5}
  exec=${exec/\$6/$6}
  run_command "${exec}"
fi

# Not found. Try substituting <name> on every second parameter starting at 4th.
for ((i=3;i<${#words[@]};i=i+2)); do
  words[i]="<name>"
done
lookup=$(printf " %s" ${words[@]})
lookup=${lookup:1}
remove_key_params "${lookup}"
exec="${COMMAND_LOOKUP[${LOOKUP_KEY?}]}"
if [[ "${exec}" != "" ]]; then
  # Do substitutions here before the function call changes the args.
  exec=${exec/\$3/$3}
  exec=${exec/\$4/$4}
  exec=${exec/\$5/$5}
  exec=${exec/\$6/$6}
  run_command "${exec}"
fi

# Fell through from the last 2 command lookups. Command not found. Print usage.
print_usage
