# Remembered Consents

## Overview

Authorized release of user information between systems may be remembered
such that users are not prompted every time. The Remembered Consents account
administration page provides a means for users to see what information releases
they have configured and to remove Remembered Consents such that they will
be prompted again for authorization in the future.

## How Remembered Consents Works

Applications may request specific categories of information about a user.
Categories include things such as:
*  User profile: name, language preference, profile picture, etc.
*  Email addresses.
*  Passport Visas: all visas or a specific set visas.
*  Scopes: names of other categories of information, or names of roles or
   permissions the user may have.

If a user agrees to release information to the requesting application, then
the user is provided several options of how to handle similar requests in the
future:
1. **Don't remember, ask me next time**: the user is requesting to be prompted
   every time similar information requests are recieved. In this case, no
   Remembered Consent entry is made.
1. **Remember my selection**: the user is requesting that a Remembered Consent
   to be created that will match on a specific application or a specific set
   of information that is being requested.
1. **Remember my selection for anything requested**: the user is requesting
   that a Remembered Consent to be created that will match any request made by
   the same application. That is, the application is allowed to recieve any
   category of information or any types of visas or scopes on the user without
   requiring further permission from the user to release that information.

The user may be given the option to unselect checkboxes to tune what information
is released to the application. When using the Remembered Consents feature,
the system remembers that "for a given user information request similar to this
one, then only release the following details about me".

## Managing Remembered Consents

Users may view a list of their Remembered Consents to see key information about
each entry:
*  **Application**: the name of the application requesting user information.
*  **Scopes**: the list of scopes that the application may request.
*  **Selected Visas**: the set of visas that the user has agreed to release as
   part of requests that match the application and scopes.
*  **Created At**: the date and time of when the Remembered Consent was created.
*  **Expires At**: if it expires, this is the date and time when the Remembered
   Consent will no longer apply, and information release requests after this
   time will prompt the user again even when the request is similar.

Users may delete a Remembered Consent, causing future similar requests to prompt
the user. Management features like `delete` may be provided via a dropdown menu
per item in the Remembered Consents list.
