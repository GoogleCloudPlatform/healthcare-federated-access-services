# How To Deploy Federated Access

## Before you start

To deploy federated access you must create a Google Cloud project. This project
will include the following:

*  dataset hosting
*  service account hosting
*  ic and dam hosting

The following projects are used for the cross project and environment scenarios:

*   Data hosting project: the GCP project hosting datasets.

    For example, this project owns the data buckets or tabular data shared with
    the researcher.

*  Service account project: the GCP project hosting service accounts for
   researchers. DAM allocates service accounts that represent the user for
   accessing dataset.

*  Server (IC/DAM) hosting project: the GCP project hosting IC and DAM server.

## Create a Google Cloud project

To create a Google Cloud project, do the following:

1.  Create a GCP project using the GCP Developer Console.

1.  Run the following setup script to deploy components with default settings
    that can be tested:

        ```bash
        export PROJECT=<gcp-project-id>
        ./deploy.bash
        ```
    This script configures the following:

     *  IC and DAM are deployed on [GAE Flex](https://cloud.google.com/appengine/docs/flexible/)
        in [us-central](https://cloud.google.com/appengine/docs/locations).
     *  [CloudSQL](https://cloud.google.com/sql/docs/postgres/) is deployed for
        [Hydra](https://github.com/ory/hydra) in [us-central1](https://cloud.google.com/sql/docs/mysql/locations)
        with the following configuration:
        *  type: "postgres"
        *  name: "hydra"
        *  username: "hydra"
        *  password: "hydra"

For more information on deploying federated access, see
[deploy.bash](/google3/third_party/hcls_federated_access/deploy.bash).
Configuration details are also contained within the following files:

*  [IC's config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/config_master_main_latest.json)
*  [IC's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/permissions_master_main_latest.json)
*  [IC's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/secrets_master_main_latest.json)
*  [DAM's config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/config_master_main_latest.json)
*  [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json)
*  [DAM's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/secrets_master_main_latest.json)

To configure a production environment, do the following:

1.  Run the following setup script:

    ```
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -RSAPublicKey_out > public.pem
    cat private.pem
    cat public.pem
    ```

1.  Edit `deploy.bash` and ensure the following is configured correctly:

    *  The CloudSQL `username` and `password`.
    *  [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json) file. This file contains a list of DAM administrators.
    *  [IC's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/permissions_master_main_latest.json) file. This file contains a list of IC administrators.
    *  [DAM's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/secrets_master_main_latest.json)
    *  [IC's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/secrets_master_main_latest.json)
    *  OAuth client credentials
    *  IDP client credentials
    *  RSA keys

**Note:** Take care to not add or change anything that can expose Hydra's admin endpoints outside the VM (nginx is configured to guard this in the sample setup).

## Install Google Cloud SDK

To install the Google Cloud SDK, in your GCP project, run the following command:

```bash
gcloud auth application-default login
gcloud auth login

export GCP_USERNAME=<project-admin-account, e.g. user@example.com>
gcloud config set account ${GCP_USERNAME?}
```

For more information, see the [SDK documentation](https://cloud.google.com/sdk/docs).

## Test with test client

In a browser, open `https://icdemo-dot-${YOUR_PROJECT_ID}.appspot.com/test` and `https://damdemo-dot-${YOUR_PROJECT_ID}.appspot.com/dam/test`
