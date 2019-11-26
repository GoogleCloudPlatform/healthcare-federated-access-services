# `healthcare-federated-access-services`

This repository contains an implementation of the
[GA4GH](https://www.ga4gh.org/) [Passport](http://bit.ly/ga4gh-passport-v1) specification.

**IMPORTANT: This is an early pre-release that should only be used for testing and demo purposes. Only synthetic or public datasets should be used. Customer support is not currently provided.**

## Contributing

See the [contributing](CONTRIBUTING.md) document for information about how to
contribute to this repository.

## Notice

This is not an officially supported Google product.

## Getting started

### Install Google Cloud SDK

https://cloud.google.com/sdk/docs

```
gcloud auth application-default login
gcloud config set account [YOUR_GCP_ACCOUNT, eg: user@example.com]
```

### Prepare Google Cloud project(s)

For minimum setup, only one project is needed.

#### Setup one project

- create a gcp project

  ```bash
  export PROJECT="[YOUR_PROJECT_NAME]"
  gcloud projects create $PROJECT --set-as-default
  gcloud config set project $PROJECT
  ```

- Setup for app engine, https://cloud.google.com/appengine/docs/standard/go112/quickstart#before-you-begin
- In the Cloud Developer Console's [IAM page](https://console.cloud.google.com/iam-admin/iam) for your project", add `Service Account Token Creator` and `IAM Admin` role to `App Engine default service account`

More information for cross project/environment scenarios:

-   data hosting project: the GCP project hosting datasets.
-   service account project: the GCP project hosting service accounts for
    researchers.
-   server (IC/DAM) hosting project: the GCP project hosting IC and DAM server.

#### Setup a server hosting project

https://cloud.google.com/appengine/docs/standard/go112/quickstart#before-you-begin

#### Setup a data hosting project

Add the IAM Admin role to the `App Engine default service account` of the server hosting project, e.g. ${server-hosting-project}@appspot.gserviceaccount.com.

#### Setup service account project

Add `Service Account Token Creator` and `Cloud KMS CryptoKey Encrypter/Decrypter` role to `App Engine default service account` of server hosting project.

### Configure

- Fill in `gcp/{dam|ic}/app.yaml`. Example:

  ```
  # dam/app.yaml
  runtime: go112
  service: "dam"

  env_variables:
    DAM_URL: "https://dam-dot-${dam-hosting-project}.appspot.com"
    SERVICE_NAME: "dam"
    PROJECT: "${dam-hosting-project}"
    CONFIG_PATH: "config"
    STORAGE: "datastore"
    DEFAULT_BROKER: "${your-ic-name-in-config-file}"

  # ic/app.yaml
  runtime: go112
  service: "ic"

  env_variables:
    SERVICE_NAME: "ic"
    SERVICE_DOMAIN: "ic-dot-${ic-hosting-project}.appspot.com"
    ACCOUNT_DOMAIN: "${account-project-domain}"
    CONFIG_PATH: "config"
    PROJECT: "${ic-hosting-project}"
    PERSONA_DAM_URL: "https://dam-dot-${dam-hosting-project}.appspot.com"
    PERSONA_DAM_CLIENT_ID: "${dam-client-id}"
    PERSONA_DAM_CLIENT_SECRET: "${dam-client-secret}"
    STORAGE: "datastore"
  ```

- In `deploy/config/dam/config_master_main_latest.json`, add your IC to "trustedPassportIssuers".

  ```
  "ic": {
      "issuer": "https://ic-dot-${ic-hosting-project}.appspot.com/oidc",
      "clientId": "${client-id}"
  },
  ```

- Generate keys for `deploy/config/{dam|ic}/secrets_master_main_latest.json`

  ```bash
  openssl genrsa -out private.pem 2048
  openssl rsa -in private.pem -RSAPublicKey_out > public.pem
  cat private.pem
  cat public.pem
  ```

### Start servers

```
gcloud app deploy gcp/ic/app.yaml
gcloud app deploy gcp/dam/app.yaml
```

### Test with test client

In browser, open `https://ic-dot-${ic-hosting-project}.appspot.com/identity/v1alpha/master/test`
