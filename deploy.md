# How To Deploy

## Prepare Google Cloud project(s)

For minimum setup, only one project is needed. The project will include:

- dataset hosting
- service account hosting
- ic and dam hosting

More information for cross project/environment scenarios:

- data hosting project: the GCP project hosting datasets. For example, this project owns the data buckets or tabular data that is being shared with the researcher.
- service account project: the GCP project hosting service accounts for
  researchers. DAM allocates service accounts that represent the user for accessing dataset.
- server (IC/DAM) hosting project: the GCP project hosting IC and DAM server.

### Install Google Cloud SDK

https://cloud.google.com/sdk/docs

```bash
gcloud auth application-default login
gcloud auth login

export GCP_USERNAME=<project-admin-account, e.g. user@example.com>
gcloud config set account ${GCP_USERNAME?}
```

### Setup one project

- create a gcp project

  ```bash
  export PROJECT=<gcp-project-id>
  gcloud projects create $PROJECT --set-as-default
  gcloud config set project $PROJECT
  ```

- enable services

We need to enable services:

- AppEngine and AppEngine flex for running IC and DAM services
- Cloud SQL as database of ory/hydra
- Datastore as database of IC and DAM
- IAM for managing service accounts accessing dataset
- CloudBuild for building the docker images
- BigQuery and GCS for dataset hosting

  ```bash
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

    gcloud app create --region=<GAE regions, see https://cloud.google.com/appengine/docs/locations>
  ```

- setup service accounts

Add IAM Roles to service account of GAE Flex `service-PROJECT_NUMBER@gae-api-prod.google.com.iam.gserviceaccount.com`:

- Cloud KMS CryptoKey Encrypter/Decrypter
- Cloud SQL Client
- Editor
- Service Account Token Creator
- Project IAM Admin

  ```bash
  PROJECT_NUMBER=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")

  gcloud projects add-iam-policy-binding -q ${PROJECT_NUMBER?} --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
  gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudsql.client
  gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/editor
  gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator
  gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${PROJECT_NUMBER?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/resourcemanager.projectIamAdmin
  ```

- setup CloudSQL

  ```bash
  # Create a CloudSQL D0 (memory=128M, disk=250G) postgres 11 instance in us-central-1.
  gcloud sql instances create hydra --database-version=POSTGRES_11 \
    --tier=db-f1-micro --region=us-central1
  # Create user: name="${NAME}", password="${PASSWORD}"
  gcloud sql users create hydra --instance=hydra --password=${PASSWORD?}
  # Create database ic
  gcloud sql databases create ic --instance=hydra
  # Create database dam
  gcloud sql databases create dam --instance=hydra
  ```

See https://cloud.google.com/sql/docs/postgres/create-instance for more options to customise your instance. It also works with MySQL instance with config changes.

Please use real username and password. The example is using user=hydra and password=hydra.

### Multiple projects: setup a data hosting project

Grant the Project IAM Admin role of the data hosting project to the `App Engine Flex default service account` of server hosting project, `service-PROJECT_NUMBER@gae-api-prod.google.com.iam.gserviceaccount.com`. Do not grand the Project IAM Admin role of the server hosting project to the service account.

## App Engine Configure

- Fill in `deploy/gae-flex/config/{ic/dam}.yaml`. Example:

  ```yaml
  # dam.yaml
  runtime: custom
  env: flex
  service: "dam"

  env_variables:
    # Service type: ic or dam
    TYPE: "dam"
    # Project id
    PROJECT: "<DAM_HOSTING_PROJECT_NAME>"

  beta_settings:
    # Pass CloudSQL instance to GAE
    cloud_sql_instances: <CLOUDSQL_PROJECT>:<CLOUDSQL_REGION see https://cloud.google.com/sql/docs/mysql/locations>:<ClOUDSQL_INSTANCE>=tcp:1234

  # ic.yaml
  runtime: custom
  env: flex
  service: "ic"

  env_variables:
    # Service type: ic or dam
    TYPE: "ic"
    # Project id
    PROJECT: "<IC_HOSTING_PROJECT_NAME>"

  beta_settings:
    # Pass CloudSQL instance to GAE
    cloud_sql_instances: <CLOUDSQL_PROJECT>:<CLOUDSQL_REGION see https://cloud.google.com/sql/docs/mysql/locations>:<ClOUDSQL_INSTANCE>=tcp:1234
  ```

## Start servers

```bash
# Build the base image. Only need to run after hydra/nginx update.
pushd deploy/gae-flex/base-image
gcloud builds submit --config cloudbuild.yaml .

popd
# Deploy IC and DAM
gcloud -q app deploy deploy/gae-flex/config/dam.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-gae:latest
gcloud -q app deploy deploy/gae-flex/config/ic.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-gae:latest
```

## Test with test client

In a browser, open `https://ic-dot-${ic-hosting-project}.appspot.com/identity/hydra-test` and `https://dam-dot-${ic-hosting-project}.appspot.com/dam/hydra-test`
