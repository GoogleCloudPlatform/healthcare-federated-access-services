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

# You need to loging to gcloud and createa a project using gcloud cli.
# Export the id of your project to environment variable PROJECT.
echo -e ${GREEN?}Starting deployment to project: ${PROJECT?}.${RESET?}
gcloud config set project ${PROJECT?}
export PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")

# Generate the config files
echo -e ${GREEN?}'Generating the config files, press enter to continue.'${RESET?}
read

cp -R ./deploy/config/ic-template/* ./deploy/config/ic/
cp -R ./deploy/config/dam-template/* ./deploy/config/dam/

sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/config_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/ic/secrets_master_main_latest.json
sed -i 's/${YOUR_PROJECT_ID}/'${PROJECT?}'/g' ./deploy/config/dam/config_master_main_latest.json

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

if [ ${FAST_DEPLOY} = "YES" ]; then
  echo -e ${GREEN?}'FAST_DEPLOY is set to YES. Skipping preparing the GCP project for deployment.' ${RESET?}
else
  echo -e ${GREEN?}'Preparing the GCP project for deployment. Press enter to continue.\nTo skip, set "FAST_DEPLOY" enviroment variable to "YES".' ${RESET?}
  # Enbable the required APIs.
  echo -e ${GREEN?}Enbable the required APIs.${RESET?}

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
  echo -e ${GREEN?}Grant the required permissions.${RESET?}

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
  echo -e ${GREEN?}Setup Cloud SQL.${RESET?}

  gcloud sql instances create hydra --database-version=POSTGRES_11 \
    --tier=db-f1-micro --region=us-central1
  # Create user: name="${NAME}", password="${PASSWORD}"
  gcloud sql users create hydra --instance=hydra --password=hydra
  # Create database ic
  gcloud sql databases create ic --instance=hydra
  # Create database dam
  gcloud sql databases create dam --instance=hydra

  echo -e ${GREEN?}Setup GCS and Update example file.${RESET?}

  gsutil mb gs://${PROJECT?}-test-dataset
  tempdir=`mktemp -d`
  pushd $tempdir
  echo "This is an example" > example.txt
  gsutil cp example.txt gs://${PROJECT?}-test-dataset
  popd
  rm -rf $tempdir

  # Deploy a simple defaut app to GAE default service.
  echo -e ${GREEN?}Deploy a helloworld to GAE default service.${RESET?}

  tempdir=`mktemp -d`
  pushd $tempdir
  git clone https://github.com/GoogleCloudPlatform/golang-samples.git
  pushd golang-samples/appengine/go11x/helloworld
  gcloud -q app deploy .
  popd
  popd
  rm -rf $tempdir

  echo -e ${GREEN?}Building Base Hydra Docker Image.${RESET?}
  gcloud builds submit --config deploy/build/hydra/cloudbuild.yaml .
fi

# Build the Personas, IC, ICDEMO, DAM, and DAMDEMO images
echo -e ${GREEN?}'Building Docker images for the services. Press enter to continue.' ${RESET?}
read

echo -e ${GREEN?}Building Personas Docker Image.${RESET?}
gcloud builds submit --config deploy/build/personas/cloudbuild.yaml .

echo -e ${GREEN?}Building IC Docker Image.${RESET?}
gcloud builds submit --config deploy/build/ic/cloudbuild.yaml .

echo -e ${GREEN?}Building ICDEMO Docker Image.${RESET?}
gcloud builds submit --config deploy/build/icdemo/cloudbuild.yaml .

echo -e ${GREEN?}Building DAM Docker Image.${RESET?}
gcloud builds submit --config deploy/build/dam/cloudbuild.yaml .

echo -e ${GREEN?}Building DAMDEMO Docker Image.${RESET?}
gcloud builds submit --config deploy/build/damdemo/cloudbuild.yaml .

# Deploy IC and DAM
echo -e ${GREEN?}'Deploying services to the GCP project. Press enter to continue.' ${RESET?}
read

echo -e ${GREEN?}Deploy PERSONAS.${RESET?}
gcloud beta -q app deploy deploy/build/personas/personas.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-personas:latest

echo -e ${GREEN?}Deploy IC.${RESET?}
gcloud beta -q app deploy deploy/build/ic/ic.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-ic:latest

echo -e ${GREEN?}Deploy ICDEMO.${RESET?}
gcloud beta -q app deploy deploy/build/icdemo/icdemo.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-icdemo:latest

echo -e ${GREEN?}Deploy DAM.${RESET?}
gcloud beta -q app deploy deploy/build/dam/dam.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-dam:latest

echo -e ${GREEN?}Deploy DAMDEMO.${RESET?}
gcloud beta -q app deploy deploy/build/damdemo/damdemo.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-damdemo:latest
