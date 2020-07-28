# Administration Concepts

## Realms

Realms allow a single deployment to give a degree of isolation between
different sets of users by providing different configuration and user session
storage.

### How Realms Work

A Realm is an isolated area that can be configured independently from other
Realms.
*  For example, an administrator can create a `staging` realm to test deployment
   upgrades and/or configuration changes before pushing them to the `production`
   Realm.
*  The `master` Realm is used to load configuration information when a Realm
   doesn't already have its own configuration settings.
   *  Once a particular type of settings are saved within a Realm, they no
      longer inherit any further updates that may be made on the `master` Realm.
*  [Resource configuration](#resources.md) are done per Realm, meaning that
   users can request resources on different Realms and receive different sets
   of resources, different policy enforcement, or differnt trust settings.
   *  This is a powerful capability as part of testing, roll-out, and user group
      isolation.
   *  It is also something that needs to be managed carefully in a production
      environment.
*  Realms are not completely independant, even after they have their own
   custom configuration settings.
   *  Some settings, such as Client Application Settings, are only available
      on the `master` Realm.
   *  Actions taken on cloud services are "flattened" from across all Realms.
   *  Some specific user activities are not stored per Realm as they are
      considered global state about a user.
