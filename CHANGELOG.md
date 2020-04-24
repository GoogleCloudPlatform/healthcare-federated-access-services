# Change Log

## [Unreleased](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/HEAD)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.2...HEAD)

## [v0.9.2](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.2)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.1...v0.9.2)

**Migration**

*  Upgrade Hydra to 1.4.2: need rebuild the base image for GAE or Re-deploy Hydra image for GKE. [commit](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/commit/d7e34f2c8c27de83e6c98620ca391b48a679e5b0)
*  Use env var `CONSENT_DASHBOARD_URL` for remembered consent management dashboard, also support set url with user id in path via ${USER_ID}. Example:
  *  `export CONSENT_DASHBOARD_URL=https://example.com/consent/${USER_ID}`

**Highlight Updates**

*  Implements remembered consents management:
  *  list user remembered consents: `/identity/v1alpha/{realm}/users/{user}/consents`
  *  delete user remembered consent: `/identity/v1alpha/{realm}/users/{user}/consents/{consent_id}`
*  Fix a multi-threading issue. [commit](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/commit/8aa9c49cc7cef5329bb1eef523b66573d864fe71)
*  Cart token exchange: responses service account key in field "service_account_key"

## [v0.9.1](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.1)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.8.8...v0.9.1)

**This is the first log of changes, it will be based on release v0.8.8 to v0.9.1.**

**Migration**

*  Upgrade GO version to 1.14: need rebuild all images, includes base image for GAE and Hydra image for GKE.
*  GCP IAM condition, the GCS dataet bucket must be "uniform access":
  *  run `gsutil uniformbucketlevelaccess set on gs://$bucket` to enable "uniform access" on bucket
  *  or turn off IAM condition via env: `export DISABLE_IAM_CONDITION_EXPIRY=true`

**Highlight Updates**

*  Implements information release page to allow user to select the information want to release, and allow user to let IC to remember user information release perference.
*  Support expiry time set on GCP IAM condition when granting user access on IAM.
