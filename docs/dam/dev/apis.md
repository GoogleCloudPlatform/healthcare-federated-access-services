# Data Access Manager APIs

Before you begin, please visit the [Concepts
Page](../../shared/admin/concepts.md) to understand API versions, realms, and
experimental features as they relate to API endpoints.

## Main Endpoints

The following are the main DAM endpoints. Users can retrieve access tokens for
resources they want using the following OIDC and DAM token checkout endpoints.

*  "/dam/login": Redirected to here from Hydra login.
*  "/dam/consent": Redirected to here from Hydra consent.
*  "/dam/oidc/loggedin": Redirected to here from Identity Broker.
*  "/dam/checkout": returns the batch of access tokens for the requested
   resources.

## Service Info Endpoints

The following are public endpoints for discovery and/or health check:

*  "/dam": metadata about the service, like versions of various services.

## Administration Endpoints

The following are administration endpoints for managing DAM.
They require "admin" permission.

*  "/dam/v1alpha/{realm}/processes": the list of background processes.
*  "/dam/v1alpha/{realm}/processes/{name}": the state of a background process.

## Admin Configuration Endpoints

The following are used for managing DAM's configuration.
They require "admin" permission access token unless otherwise noted below.

*  "/dam/v1alpha/{realm}/clients:sync": syncs client information
   between the DAM and Hydra where the DAM's configuration is considered the
   source of truth.
   *  Syncing generally happens as configurations change, but this endpoint
      allows an administrator or tool to invoke it explicitly.
   *  It does not require an admin access token, but does require the client
      (identified by the `client_id`) has the `sync` scope set in the
      configuration.
   *  Syncing is limited to once per minute.
*  "/dam/v1alpha/{realm}": supports GET and DELETE of a realm.
*  "/dam/v1alpha/{realm}/config" and sub-resources: managing configuration.
*  "/dam/v1alpha/{realm}/config/reset": resets the config to its initial version read from configuration file.
*  "/dam/v1alpha/{realm}/config/history": history of configuration changes.
*  /dam/v1alpha/{realm}/tests": performs a set of tests for validity of the current configuration.

## Users, Tokens, and Consents Management Endpoints

The following implements a subset of [SCIM V2 API](https://tools.ietf.org/html/rfc7644#section-3.2).

*  "/identity/scim/v2/{realm}/Groups": user group management, based on
   [SCIM V2 Group Resource Schema](https://tools.ietf.org/html/rfc7643#section-4.2).

See the IC's SCIM notes for limitations of use that also apply to the DAM.

The following are Token Management endpoints:

*  "/dam/v1alpha/{realm}/users/{user}/tokens": list user tokens.
*  "/dam/v1alpha/{realm}/users/{user}/tokens/{token_id}": delete user token.

## Audit logs

*  "/dam/v1alpha/{realm}/users/{user}/auditlogs": view auditlogs of user.

## Non-Admin Configuration Endpoints

The following provide read-only access to non-admins for various parts of
DAM configuration. They filter out sensitive parts of the configuration.
They require valid "client_id" and "client_secret" parameters on the request.

*  /dam/v1alpha/{realm}/client/{name}
*  /dam/v1alpha/{realm}/damRoleCategories
*  /dam/v1alpha/{realm}/resources
*  /dam/v1alpha/{realm}/resources/{name}
*  /dam/v1alpha/{realm}/flatViews
*  /dam/v1alpha/{realm}/localeMetadata
*  /dam/v1alpha/{realm}/passportTranslators
*  /dam/v1alpha/{realm}/resources/{name}/views
*  /dam/v1alpha/{realm}/resources/{name}/views/{view}
*  /dam/v1alpha/{realm}/resources/{name}/views/{view}/roles
*  /dam/v1alpha/{realm}/resources/{name}/views/{view}/roles/{role}
*  /dam/v1alpha/{realm}/services
*  /dam/v1alpha/{realm}/testPersonas
