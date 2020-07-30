# Administration Concepts

## Realms

Realms allow a single deployment to give a degree of isolation between
different sets of users by providing different configuration and user session
storage.
*  Realms can be used to experiment with different configurations. For
   example, an administrator could introduce "staging" and "prod" realms to
   test upcoming config changes.
*  Realms can be used to separate different usage scenarios from each other.
   For example, two different departments within one organization can each
   have their own realm with different configurations.
*  **Realms do not have any additional protection against use**, so all users
   and administrators of any one realm may have the ability to access other
   realms if they choose to.

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

## API Version

`v1alpha` is the current API version of these components and is used as part of
the resource path on most endpoints. Some standard OIDC endpoints, metadata
endpoints, and other API integration endpoints do not include the API version.

**Note:** `v1alpha` APIs are subject to more rapid changes without maintaining
backwards compatibility. Integrations with this API can therefore expect to need
more maintenance.

## Experimental Features

Some of the API are restricted to "experimental" usage, and are not appropriate
for production workloads and may not meet security requirements in their current
form. These are often newer features that are not yet ready for adoption.
*  Setting the following environment variable enables these experimental
   features. They are not enabled by default.
      ```
      export FEDERATED_ACCESS_ENABLE_EXPERIMENTAL=true
      ```
*  Experimental features are expected to change more significantly and more
   frequently than non-experimental parts of the API.
*  Experimental features are more likely to be removed in the future based
   on feedback and evolution of the features they represent.

