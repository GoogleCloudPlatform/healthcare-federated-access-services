# Identity Concentrator APIs

Before you begin, please visit the [Concepts
Page](docs/shared/admin/concepts.md) to understand API versions, realms, and
experimental features as they relate to API endpoints.

### Main Endpoints

The following are the main IC endpoints:

*  "/identity/v1alpha/{realm}/login/{name}": As part of a login flow from the
   login page, the user selects an Identity Provider ("IdP") to use to
   authenticate ("login"). The login page redirects the user session to this
   endpoint to initiate the login flow with the `name` of a specific IdP.
*  "/identity/v1alpha/{realm}/loggedin/{name}": Redirected here from an IdP.
*  "/identity/v1alpha/{realm}/inforelease": Redirected here from claim release consent page.
*  "/identity/login": Redirected to here from [Hydra](https://github.com/ory/hydra) login.
*  "/identity/consent": Redirected to here from Hydra consent.
*  "/identity/loggedin": Redirected to here from [Passport Broker](https://bit.ly/ga4gh-passport-v1#passport-broker).

### Service Info Endpoints

The following are public endpoints for discovery and/or health check:

*  "/identity": metadata about the service, like versions of various services.
*  "/visas/jwks": signing keys for visas issued by the IC. Note that this is a
   different set of keys than those used for signing IC tokens authored by
   OAuth2 endpoints.

### Admin Configuration Endpoints

The following are used for managing IC's configuration.
They require the "admin" permission access token unless otherwise noted below.

*  "/identity/v1alpha/{realm}/clients:sync": syncs client information
   between the IC and Hydra where the IC's configuration is considered the
   source of truth.
   *  Syncing happens as configurations change. This endpoint allows an
      administrator or tool to invoke it explicitly.
   *  It does not require an admin access token, but does require that the
      client (identified by the `client_id`) has the `sync` scope set in the
      configuration.
   *  Syncing is limited to once per minute.
*  "/identity/v1alpha/{realm}/config" and sub-resources: managing configuration.
*  "/identity/v1alpha/{realm}/config/reset": resets the configuration to its initial version read from configuration file.
*  "/identity/v1alpha/{realm}/config/history": history of configuration changes.

### Users, Tokens, and Consents Management Endpoints

The following implements a subset of [SCIM V2 API](https://tools.ietf.org/html/rfc7644#section-3.2).

*  "/identity/scim/v2/{realm}/Users": user management, based on the
   [SCIM V2 User Resource Schema](https://tools.ietf.org/html/rfc7643#section-4.1).
*  "/identity/scim/v2/{realm}/Me": based on the
   [SCIM V2 Me Authenticated Subject Alias](https://tools.ietf.org/html/rfc7644#section-3.11).
*  "/identity/scim/v2/{realm}/Groups": user group management, based on
   [SCIM V2 Group Resource Schema](https://tools.ietf.org/html/rfc7643#section-4.2).

SCIM-like endpoints have the following user management limitations:

*  See "proto/scim/v2/users.proto" and "proto/scim/v2/groups.proto" for details
   of the structure that is supported.
*  Account management updates require the `account_admin` scope on the access
   token.
*  A [limited subset of filters](#scim-filters) is available.
*  Only a limited number of object attributes (i.e. object fields) are available
   for PATCH. For example, `primary` for emails and `value` for photos.

#### Account Linking

You can link accounts using the following extension to SCIM V2:

1. Account 1: Login to the IC with the both the `account_admin` and `link`
   scopes.
2. Account 2: Login to the IC with another account with `account_admin` and
   `link` scopes.
3. Make a PATCH request to `/identity/scim/v2/{realm}/Me` while providing Account
   1 and Account 2 bearer tokens via the `Authorization` and
   `X-Link-Authorization` headers, and a body that contains a patch operation
   as follows:

       ```
       {
           "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
           "Operations":[
               { "op": "add", "path": "emails", "value": "X-Link-Authorization" }
           ]
       }
       ```

The following is a code sample of a PATCH request to link accounts given
variables (`serviceURL`, `clientId`, `clientSecret`, `token1` and `token2`):

```
let patch = `{"schemas":["urn:ietf:params:scim:api:messages:2.0:PatchOp"],"Operations":[{"op":"add","path":"emails","value":"X-Link-Authorization"}]}`;
$.ajax({
    url: `${serviceURL}/identity/scim/v2/master/Me?client_id=${clientId}&client_secret=${clientSecret}`,
    type: "PATCH",
    contentType: "application/json; charset=utf-8",
    dataType: "json",
    data: patch,
    processData: false,
    beforeSend: function(xhr){
        xhr.setRequestHeader('Authorization', `Bearer ${token1}`);
        xhr.setRequestHeader('X-Link-Authorization', `Bearer ${token2}`);
    },
    success: function(resp) {
        console.log("LINK ACCOUNT SUCCESS:\n\n" + JSON.stringify(resp, undefined, 2));
    },
    error: function(err, status, info) {
        console.log(JSON.stringify(err, undefined, 2) + `,\nstatus: "${status}", info: "${info}"`);
    }
});
```

#### SCIM Filters

**Note:** DAM and IC support only a subset of the SCIM V2 filter specification
and only on supported user management endpoints where appropriate.

SCIM-like filters that are supported by DAM and IC are defined as follows:

```
<expr> = <attribute> <compare_op> "string" | <attribute> <compare_op> boolean
```

*  **`attribute`** - an attribute path such as `active` or `name.formatted`
*  **`compare_op`** - a comparison operator such as `eq` (equals), `co` (contains),
   etc. For documentation for the full list of filter operators, see
   [SCIM V2 Filtering](https://tools.ietf.org/html/rfc7644#section-3.4.2.2).
*  `string` or `boolean` is based on the `attribute` type.

Multiple clauses within filter expressions are limited to the following:

```
<expr> or <expr> or ...

<expr> and <expr> and ...

(<expr> or <expr> or ...) and (<expr> or <expr> or ...) and <expr>
```

Brackets may be used to nest `or` clauses only, with `and` being
used between bracketed clauses to support expressions that are in
[Conjunctive Normal Form](https://en.wikipedia.org/wiki/Conjunctive_normal_form).
Brackets are not needed on sub-expressions between `and` clauses if each
such sub-expression contains no `or` subclauses. See example above ending in
`... and <expr>` without parentheses around `<expr>`.

When using filters to patch a specific object in a list, use `$ref` as the
filter for that object. For example:

```
{
    "op": "replace",
    "path": "emails[$ref eq \"email/persona/non-admin\"].primary",
    "value":"true"
}
```

#### Tokens and Consents

The following are Consents Management endpoints:

*  "/identity/v1alpha/{realm}/users/{user}/consents": list user remembered consents.
*  "/identity/v1alpha/{realm}/users/{user}/consents/{consent_id}": revoke user remembered consent.

The following are Token Management endpoints:

*  "/identity/v1alpha/{realm}/users/{user}/tokens": list user tokens.
*  "/identity/v1alpha/{realm}/users/{user}/tokens/{token_id}": delete user token.

#### Audit logs

*  "/identity/v1alpha/{realm}/users/{user}/auditlogs": view auditlogs of user.

    *  Required user token or admin token
    *  `page_size` type int, required query param
    *  `page_token` type string, query param, not required, used to access next page of auditlogs
    *  `filter` type string, query param, not required, only supports filter by time in RFC3339. example: `time>=2020-01-01T01:00:00Z AND time<=2020-01-10T01:00:00Z`


### Non-Admin Configuration Endpoints

The following provide read-only access to non-admins for various parts of
IC configuration. They filter out sensitive parts of the configuration.

*  "/identity/v1alpha/{realm}/identityProviders"
*  "/identity/v1alpha/{realm}/clients/{name}"
*  "/identity/v1alpha/{realm}/localeMetadata"
*  "/identity/v1alpha/{realm}/passportTranslators"

### Static Page Assets

The following static page assets are used:

*  "/identity/static"
