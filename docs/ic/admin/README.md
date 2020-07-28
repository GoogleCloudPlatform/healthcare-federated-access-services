# Identity Concentrator Administration

## Overview

Identity Concentrator (IC) administration functions are divided into 2 main
categories:

1. **Users and Groups**:
   *  [User administration](../../shared/admin/users/users.md) provides a means
      to find user accounts using a search tool, and then perform actions on
      user accounts.
      *  Administrators can view and update accounts in a similar way to how
         users conduct their own [account
         management](../../shared/account/README.md).
      *  Administrators can also disable accounts using a feature only available
         to administrators. This suspends the account and blocks further use
         of the account, which behaves differently than closing an account.
   *  [Group administration](../../shared/admin/users/groups.md) allows
      administrators to define groups and include or remove users from those
      groups.

1. **Configuration Settings**:
   *  [Identity Providers](config/identity-providers.md) determines which set of
      Passport and Visa issuers are trusted to provide user identity and visa
      information for use with the system.
   *  [Options](config/options.md) configure system-wide behavior of the IC.
      Some options may vary by [Realm](../../shared/admin/concepts.md#realms).
   *  [Client Applications](config/clients.md) configures a set of applications
      that are allowed to make API calls into various functions with the IC.
