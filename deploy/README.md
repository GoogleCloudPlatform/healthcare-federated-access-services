# Deploy on Google App Engine Flex

See the [README](../README.md) file in project root for other requirements and
steps.

This deployment will create a docker container run on Google App Engine Flex
bundled a bundle of services:

- [nginx](https://www.nginx.com/) accepts incoming http request
- [hydra](https://github.com/ory/hydra) resolves oauth/oidc requests
- **IC or DAM** resolves IC/DAM requests.

In addition, the testing playground deployment services will be deployed:

- Personas Broker for test accounts, including administration privledges
- IC demo test page service ("icdemo")
- DAM demo test page service ("damdemo")

**Important:** The default deploy script is not for use with production data.
See the [playground deployment script documentation](docs/playground/deploy.md)
for more information.

## Deployment Service Dependencies in GCP

1. [GAE flex](https://cloud.google.com/appengine/docs/flexible/custom-runtimes/quickstart)
2. [CloudSQL](https://cloud.google.com/sql/docs/mysql/quickstart) for Hydra
3. [CloudBuild](https://cloud.google.com/source-repositories/docs/quickstart-triggering-builds-with-source-repositories)

The deployment will make use of IAM Roles for a GAE Flex service account
`service-${PROJECT_NUMBER}@gae-api-prod.google.com.iam.gserviceaccount.com`:

- App Engine flexible environment Service Agent
- Cloud KMS CryptoKey Encrypter/Decrypter
- Cloud SQL Client
- Editor
- Service Account Token Creator

**Tip:** for details, view the `deploy.bash` script for specific steps
performed.

## Users and Databases in CloudSQL

Currently, the deployment makes use of:

*   **username**: hydra
*   **password**: hydra
*   **database name**: `<GAE service name>` (eg. ic, dam).

## Update the base image

To speed up the build, the deployment script also pushes the base image to GCR.
This includes `golang`, `nginx` and `hydra`.

## Run deploy script

See the [playground deployment instructions](docs/playground/deploy.md) to
perform a deployment with a testing playground configuration.

## Appendix:

- [Connecting to Cloud SQL from App Engine](https://cloud.google.com/sql/docs/mysql/connect-app-engine)
