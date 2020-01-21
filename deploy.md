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

- create a gcp project using the GCP Developer Console.
- the following setup script deploys components with some default settings and is useful for testing (for production deployments, see a section below):
  - IC and DAM are deployed on [GAE Flex](https://cloud.google.com/appengine/docs/flexible/) in [us-central](https://cloud.google.com/appengine/docs/locations)
  - [CloudSQL](https://cloud.google.com/sql/docs/postgres/) is deployed for [Hydra](https://github.com/ory/hydra) in [us-central1](https://cloud.google.com/sql/docs/mysql/locations):
    - type: "postgres"
    - name: "hydra"
    - username: "hydra"
    - password: "hydra"

  ```bash
  export PROJECT=<gcp-project-id>
  ./deploy.bash
  ```

- see `deploy.bash` for more details, also check config files:
  - [IC's config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/config_master_main_latest.json)
  - [IC's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/permissions_master_main_latest.json)
  - [IC's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/secrets_master_main_latest.json)
  - [DAM's config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/config_master_main_latest.json)
  - [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json)
  - [DAM's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/secrets_master_main_latest.json)
- for production environments, please review the `deploy.bash` script and make edits to the setting indicated above, paying special attention to security configuration such as:
  - CloudSQL `username` and `password`.
  - [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json) file list of DAM administrators.
  - [IC's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/permissions_master_main_latest.json) file list of IC administrators.
  - [DAM's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/secrets_master_main_latest.json) [IC's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/secrets_master_main_latest.json) OAuth client credentials, Idp client credentials and RSA keys for signing.

    ```
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -RSAPublicKey_out > public.pem
    cat private.pem
    cat public.pem
    ```

- also take extra care to not add or change anything that can expose Hydra's admin endpoints outside the VM (nginx is configured to guard this in the sample setup).

## Test with test client

In a browser, open `https://ic-dot-${ic-hosting-project}.appspot.com/identity/hydra-test` and `https://dam-dot-${dam-hosting-project}.appspot.com/dam/hydra-test`
