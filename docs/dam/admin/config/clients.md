# Client Application Configuration

## Overview

A client, i.e. "Client Application", is an application or service that directly
makes service endpoint calls into the Data Access Manager (DAM). Each client
must be registered with the DAM before being able to use it.

By having only Trusted Clients use the DAM, it limits the ability for other
applications, some which may be less secure or even malicious, to be able to get
their hands on a valid access token and use the DAM's API as these other 3rd
party services would also need to be registered as a Trusted Client in order to
make such API calls.

## Client Registration

An administrator will need to register each Client Application with the DAM,
and provide the `Client Identifier` and `Client Secret` to the application for
it to make DAM API calls.

Client Applications have users sign in to use the DAM, such as request
resources. These authentication flows ("auth flows") that the user takes follow
OIDC standards. To better understand the parameter settings listed below for a
client registration, please refer to the [OIDC
specification](https://openid.net/specs/openid-connect-core-1_0.html)

1. **Scope**: A space-separated list of scopes that the Client Application may
   request when having the user sign in to the DAM as part of an OIDC
   authentication flow. Common options include:
   *  **openid**: standard for using OIDC auth flows.
   *  **offline**: when the application needs offline access as defined by
      OAuth2.0.
   *  **identities**: to include a set of alternative identities this user is
      also known as. This is important when requesting administrator access.

1. **Redirect URIs**: A list of URLs that are allowed to be included in this
   client's `redirect_uri` parameter during an OIDC auth flow. That is, at the
   end of signing in a user to use the DAM, these are pages where the user will
   be redirected to after the sign in completes. If a redirect page is requested
   that is not on this list, an error will be given.

1. **Grant Types**: Choose one or more standard OIDC grant types for the auth
   flow being used.

1. **Response Types**: Chose one or more standard OIDC response types that match
   how your application will make use of the response given at the end of an
   auth flow.

### Client Registration Response

The response of registration includes the following important information:

*  **Client Identifier**: a unique identifier, often an abstract string such
   as a GUID, that represents the DAM on within the Issuer's system.
*  **Client Secret**: an opaque string that is stored by the DAM that should
   only be known by the DAM and the Issuer. This should be safeguarded such
   that no other person or service can use it to impersonate the DAM.

Note: **The client secret will not be available via the API to retrieve again
later**. You should copy and paste it where it is needed, but also take care not
to expose the secret to others wherever it is stored.
