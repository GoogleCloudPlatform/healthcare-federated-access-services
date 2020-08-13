# Change Log

## [Unreleased](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/HEAD)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.10...HEAD)

## [v0.9.10](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.10)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.9...v0.9.10)

**Migration**

* Remove any references to "whitelistedRealms" from DAM or IC configs as part of
  upgrading to this release. These options are no longer recognized and will
  generate errors if present in configs.

## [v0.9.9](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.9)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.8...v0.9.9)

**Highlight Updates**

* Introduce LRO processes: Includes an implementation of realm deletion using
  this infrastructure.

**Migration**

* Move `/identity/scim/...` endpoints to `/scim/...` endpoints (i.e. "scim" is
  at the path root).
  * **IMPORTANT**: applications should move to use the new paths as the
    older path endpoints will be removed shortly.
* localeMetadata endpoints now return UI objects with more information instead
  of strings as the values within the maps.

```
{
  "locales": {
    "uz-Arab-AF": {
      "base": "uz",
      "region": "AF",
      "script": "Arab",
      "ui": {
        "label":        "Uzbek (Arabic, Afghanistan)",
        "language":     "Uzbek",
        "region":       "Afghanistan",
        "script":       "Arabic",
      }
    },
    ...
  },
  "timeZones": {
    "America/Indiana/Indianapolis": {
      "ui":
        "label":     "Indianapolis (Indiana, America)",
        "city":      "Indianapolis",
        "region":    "America",
        "subregion": "Indiana",
      }
    },
    ...
  }
```

## [v0.9.8](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.8)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.7...v0.9.8)

** Highlight Updates**

* Add localeMetadata endpoints on DAM and IC to list canonical choices to aid
  with UI selection on the user profile page.

## [v0.9.7](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.7)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.6...v0.9.7)

**Highlight Updates**

* Add information release page on DAM
* Add information release management endpoints on DAM:

  * GET "/dam/v1alpha/{realm}/users/{user}/consents"
  * DELETE "/dam/v1alpha/{realm}/users/{user}/consents/{consent_id}"

## [v0.9.6](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.6)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.5...v0.9.6)

**Highlight Updates**

* Support scim user endpoint on DAM
* Support "filter" in auditlogs:

  * add filter "decision". example: decision = "PASS" or decision = "FAIL"

**Migration**

* Update traffic router for dam to expose `/identity/scim` scim endpoints on DAM. [example](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/build-templates/dam/nginx.conf)

## [v0.9.5](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.5)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.4...v0.9.5)

**Highlight Updates**

* Support "filter" in auditlogs:

  * time >= or <= RFC3339 timestamp, example: time >= "2020-06-05T16:03:01+00:00"
  * type = REQUEST or POLICY for audit log types, example: type = "REQUEST"
  * text = or :(contains) for any text field equals or conatins given words, example: text : "a" or text = "a"

## [v0.9.4](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.4)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.3...v0.9.4)

**Highlight Updates**

* Add CSP header to restrict resource origin.
* Use KMS to sign visa and gatekeeper token

**Migration**

* Update secret config in datastore, you can use `import.bash`
* The SA for IC/DAM service accessing GCP services requires new role `roles/cloudkms.signerVerifier`

## [v0.9.3](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.3)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.2...v0.9.3)

**Migration**

* Need to import `permissions` file in IC and DAM into datastore, for test setup just run `import.bash` with `-t`

**Highlight Updates**

* Implements token management endpoints:

  * List tokens of user: `GET /(identity|dam)/v1alpha/users/{user}/tokens`
  * Delete token of user: `DELETE /(identity|dam)/v1alpha/users/{user}/tokens/{token_id}`

* Implements audit logs endpoints:

  * List audit logs of user `GET /(identity|dam)/v1alpha/users/{user}/auditlogs`.

* Passport Visa [Embedded Document format](https://github.com/ga4gh/data-security/blob/master/AAI/AAIConnectProfile.md#embedded-document-token-format) restriction:

     * JKU URL in the JWT header is now restricted to issuer's domain as found in the `iss` claim, otherwise the visa will be rejected.

## [v0.9.2](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.2)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.9.1...v0.9.2)

**Migration**

* Upgrade Hydra to 1.4.2: need rebuild the base image for GAE or Re-deploy Hydra image for GKE. [commit](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/commit/d7e34f2c8c27de83e6c98620ca391b48a679e5b0)
* Use env var `CONSENT_DASHBOARD_URL` for remembered consent management dashboard, also support set url with user id in path via ${USER_ID}. Example:
  * `export CONSENT_DASHBOARD_URL=https://example.com/consent/${USER_ID}`

**Highlight Updates**

* Implements remembered consents management:
  * list user remembered consents: `/identity/v1alpha/{realm}/users/{user}/consents`
  * delete user remembered consent: `/identity/v1alpha/{realm}/users/{user}/consents/{consent_id}`
* Fix a multi-threading issue. [commit](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/commit/8aa9c49cc7cef5329bb1eef523b66573d864fe71)
* Cart token exchange: responses service account key in field "service_account_key"

## [v0.9.1](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/tree/v0.9.1)

[Full Changelog](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/compare/v0.8.8...v0.9.1)

**This is the first log of changes, it will be based on release v0.8.8 to v0.9.1.**

**Migration**

* Upgrade GO version to 1.14: need rebuild all images, includes base image for GAE and Hydra image for GKE.
* GCP IAM condition, the GCS dataet bucket must be "uniform access":
  * run `gsutil uniformbucketlevelaccess set on gs://$bucket` to enable "uniform access" on bucket
  * or turn off IAM condition via env: `export DISABLE_IAM_CONDITION_EXPIRY=true`

**Highlight Updates**

* Implements information release page to allow user to select the information want to release, and allow user to let IC to remember user information release perference.
* Support expiry time set on GCP IAM condition when granting user access on IAM.
