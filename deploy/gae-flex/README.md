# Deploy on Google App Engine Flex

See the readme file in project root for other requirements and steps.

This deployment will create a docker container run on Google App Engine Flex with service:

- [nginx](https://www.nginx.com/) accepts incoming http request
- [hydra](https://github.com/ory/hydra) resolves oauth/oidc requests
- **IC or DAM** resolves IC/DAM requests.

## Enable Service in GCP

1. [GAE flex](https://cloud.google.com/appengine/docs/flexible/custom-runtimes/quickstart)
2. [CloudSQL](https://cloud.google.com/sql/docs/mysql/quickstart) for Hydra
3. [CloudBuild](https://cloud.google.com/source-repositories/docs/quickstart-triggering-builds-with-source-repositories)

Add IAM Roles to service account for GAE Flex `service-PROJECT_NUMBER@gae-api-prod.google.com.iam.gserviceaccount.com`:

- App Engine flexible environment Service Agent
- Cloud KMS CryptoKey Encrypter/Decrypter
- Cloud SQL Client
- Editor
- Service Account Token Creator

```bash
PROJECT=$(gcloud config get-value project)
NUM=$(gcloud projects list --filter="${PROJECT?}" --format="value(PROJECT_NUMBER)")
gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${NUM?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudkms.cryptoKeyEncrypterDecrypter
gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${NUM?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/cloudsql.client
gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${NUM?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/editor
gcloud projects add-iam-policy-binding -q ${PROJECT?} --member serviceAccount:service-${NUM?}@gae-api-prod.google.com.iam.gserviceaccount.com --role roles/iam.serviceAccountTokenCreator
```

## Create user and database in CloudSQL

Currently, it is using username: hydra, password: hydra, database name: GAE service name (eg. ic, dam).

## Update the base image

To speed up the build, we also push the base image to gcr which include golang, nginx and hydra.

```bash
cd deploy/gae-flex/base-image
gcloud builds submit --config cloudbuild.yaml .
```

## Run deploy script

Replace `Your_Project_ID` in `deploy/gae-flex/build/Dockerfile` and yaml files under `deploy/gae-flex/build/config/`. Then

```bash
gcloud builds submit --config gae-cloudbuild.yaml --substitutions=_VERSION_="latest" .
gcloud -q app deploy deploy/gae-flex/config/dam.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-gae:latest
gcloud -q app deploy deploy/gae-flex/config/ic.yaml --image-url=gcr.io/${PROJECT?}/hcls-fa-gae:latest
```

## Appendix:

- [Connecting to Cloud SQL from App Engine](https://cloud.google.com/sql/docs/mysql/connect-app-engine)
