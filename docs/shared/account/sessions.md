# User Sessions

## Overview

Each time a user signs in, a new user session is created and a set of access
tokens are provided to the application being used to represent that user when
making user requests to other backend services.

These sessions are stored and sessions can be managed by the user as well as
system administrators.

## Composition of a Session

User Sessions typically are composed of these key parts:

1. **Issued At**: When the session was created, or the last set of tokens for
   that session.

1. **Name**: The internal unique name for the session. This is system-level name
   and is not intended to be user-friendly, however the backend systems use this
   name as part of session management.

1. **Issuer**: The URL of the service that created the session.

1. **Scopes**: The information or permissions available to the session. Examples
   include:
   *  **openid**: Created by a standard sign-in flow using the OIDC protocol.
   *  **ga4gh_passport_v1**: Access to the user's Passports and Visas details
      as well as any qualifications and permissions those represent.
   *  **account_admin**: Able to manage the user account settings.
   *  **offline_access**: A system service is able to use the session without
      further user interation.

1. **Expires At**: When the most recent session token will expire and no longer
   be accepted by backend systems to represent the user.

1. **Application**: The name of the application that is using the session.

## Managing Sessions

Sessions provide a menu of options that can take action on each session:

1. **Revoke**: Request that the session remove the ability to extend itself.
   *  Even when getting confirmation of revocation, this may take time to take
      affect as existing access tokens will need to individually expire and
      attempt to be renewed.
   *  The cycle of renewal varies, and is managed as part of system setup and
      is therefore not in control of the user.

In the future, there may be more options available from the menu.

There are other actions that can be taken manually with sessions. For example,
use the `Session Name` to search for [Audit Logs by
text](logs.md#search-audit-logs).
*  This reveals actions taken by the session with various backend services.
