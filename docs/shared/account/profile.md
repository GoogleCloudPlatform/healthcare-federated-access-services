# Account Profile

## Overview

An account profile provides basic information about a user for use by
applications.

## Profile Information

The account profile may include:

1. **Display Name**: This is the way the user wishes to see their name or be
   referred to by others using the system.

1. **Enabled**: This can only be controlled by the system administrator.
   *  When an account is disabled, the user is no longer able to sign in and use
      the system.
   *  This is different from removing an account.
      *  Removed accounts can be added back again later by the same user should
         the user wish to resume using the system.
      *  Disabled accounts are locked by the adminstrator.
   *  While attempting to sign in, the application may show an error message
      indicating that the account has been disabled.
   *  Users should contact their system administrator for more information on
      how to bring the account back into good standing.

1. **First Name**: The person's "given name".

1. **Middle Name**: The person's "middle name" or names (space separated).

1. **Last Name**: The person's family name.

1. **Locale**: The display format preference for dates, times, and currencies.
   *  Some applications may also use this locale setting to determine the
      language preference if `Language` is not provided.

1. **Language**: The written language preference for text or audio, depending
   on the application.

1. **Emails**: A list of email addresses associated with this account.
   *  One email account can be marked as `primary`, indicating it is the
      preferred email address to contact the user.
   *  There can be more than one email address provided using the [Linked
      Accounts](linked-accounts) feature available to some sign-in services
      (Identity Providers).

1. **Photos**: A list of thumbnails that represent the user.
   *  These are mostly imported from the accounts the user has made use of to
      sign into the system.
   *  One photo can be marked as `primary`, indicating it is the preferred
      thumbnail to use to represent the user's account.

## Linked Accounts

The Identity Concentrator (IC) provides a way to link accounts together
to provide the following benefits:
*  **Convenience**: A user can sign into one account and get access to all their
   information across multiple accounts.
   *  Streamlines the process in a number of cases.
   *  Less tracking of what account to use in various circumstances and
      environments by keeping accounts together.
*  **Collect permissions**: centralize qualifications and permissions in the
   form of Passport Visas, into one account.
   *  This can allow the user to provide evidence that they meet a particular
      set of criteria that may not be easy to do if signing into accounts
      seperately.
   *  Provide a central location for a user to see if they have all the
      qualifications they need, or if they need to apply for more to meet the
      needs of a particular access policy.

Linked accounts are verified by the sign-in service as belonging to a particular
user by having the user provide proof of account ownership, usually in the form
of a password, and/or multi-factor authentication scheme, etc.
*  Because account ownership needs to be verified, the user is not provided a
   way to simply type in their list of email addresses.
*  The system is configured to allow accounts from particular sign-in service
   (identity) providers to be eligable for linking accounts.
