# Data Access Manager Administration

## Overview

Data Access Manager (DAM) administration functions are divided into 4 main
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

1. **Resource Management**:
   *  [Resource definitions](config/resources.md) make data and services
      available to users that meet defined policies for access.
   *  [Access Policy definitions](config/policies.md) specify a set of criteria
      that users must meet in order to gain or retain access to resources.
   *  [Test Personas](config/personas.md) can be defined to ensure the the
      behavior of access policies meet the intended expectations about which
      users will have access and which users will be denied access.

1. **Trust Configuration**:
   *  [Trusted Issuers](config/issuers.md) determines which set of Passport and
      Visa issuers are trusted to provide user identity and visa information for
      use with the system, and specifically for use within access policies.
   *  [Visa Sources](config/sources.md) create lists of organizations that are
      trusted as sources of authority for visas. Access policies may make use
      one or more Visa Source lists to indicate which sources of authority are
      applicible in a particular access scenario.
   *  [Client Applications](config/clients.md) configures a set of applications
      that are allowed to make API calls into various functions with the DAM.

1. **Advanced Settings**:
   *  [Options](config/options.md) configure system-wide behavior of the DAM.
      Some options may vary by [Realm](concepts.md#realms).
   *  [Visa Types](config/visa-types.md) define the set of Visa Types that are
      available for the DAM to make use of.
   *  [External Services](config/services.md) provide very advanced
      configuration settings to map how access to resources will make use of
      underlying cloud or custom services that provide data, APIs, and compute.