# Audit Logs

## Overview

User interactions with the system may produce a number of activity logs. These
logs can be reviewed for audit purposes to review use of the system by a given
user. This can be helpful, especially when troublehshooting a problem or when
a security issue with an account is suspected.

## Composition of an Audit Log Entry

Audit logs typically are composed of these key parts:

1. **Log Entry Identifier**: This is a unique identifier for the user of the
   log entry. It can be referred to when discussing activity between a system
   adminstrator and a user, for example.

1. **Log Type**: Indicates whether the log entry is a `REQUEST` log entry or a
   `POLICY` log entry.
   *  `REQUEST` log entries indicate that an application made a system request
      to the system on behalf of the user. Note that system requests can be very
      detailed, and there may be multiple system requests to accomplish one
      higher-level user request.
   *  `POLICY` log entries indicate that the user requested access to a
      particular resource, such as a dataset or system service.
      *  Such a request needed to evaluate a `policy` to determine if access
         may be granted.
      *  The system evaluated user information that was made available to
         determine if access is appropriate.
      *  The result of this determination is also recorded as part of the log
         entry.

1. **Time**: When the event occurred.

1. **Decision**: A `PASS` or `FAIL` decision that the system made during the
   `REQUEST` or `POLICY` evaluation.

1. **Resource Name**: More details about what the event was processing, such as
   the name of the request or the name of a dataset.

## Viewing Audit Logs

When viewing a list of audit log entries, there may be more details available:

1. **Caller IP**: The IP Address of the application that made the system
   request.

1. **Method Name**: The method (type of operation) being performed during the
   system request.

1. **Service Name**: The name of the backend system service that processed the
   request.

1. **Service Type**: The type of role or API that the backend system service
   provides. Typically this is either `DAM` (Data Access Manager) or `IC`
   (Identity Concentrator).

1. **Token ID**: The user identity session's access token that was used to
   perform the request on behalf of the user.
   *  This is useful when trying to determine if an access token had been leaked
      or is otherwise being used in a way that is unexpected by the user.
   *  Individual tokens may be revoked via matching the `Token ID` within the
      [Account Sessions](sessions.md) management function. This can limit future
      use of the token once the revocation can take effect.

1. **Token Issuer**: The URL of the service that created the `Token ID` to
   represent the user during system requests.

1. **Token Subject**: A user account identifier. This is not necessarily the
   same as an email address. For example:
   *  Data Access Managers (DAMs) produce Token Subjects starting with `dam`.
   *  Identity Concentrators (ICs) produce Token Subjects starting with `ic`.
   *  Other Identity Providers may use other schemes to create subjects. Some
      may look like email addresses because they can contain an `@` symbol, but
      still may not be an email address for the user.

## Search Audit Logs

The following features are available to find audit logs of interest:

1. **Search by text**: searches across various text fields listed above to find
   log entries that contain the all the words within a single log entry.

1. **Log Type**: limit results by `REQUEST` or `POLICY` log type.

1. **Decision**: limit results by those having either a `PASS` or `FAIL`
   decision or result.

1. **Log entries per page**: limit the number of log entries shown per page of
   results.
