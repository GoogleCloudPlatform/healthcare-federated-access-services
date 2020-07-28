# Group Administration

## Overview

Groups contain a collection of users that are useful for specifying in an
`allowlist` policy or other system permissions.

## Creating Groups

Only a system administrator is able to create a group.

1. **Create a Group**: Add a group to via the group management feature.

1. **Add Members**: List a set of members to add to the group.
   *  May be an email address of the form `person@example.org`.
   *  May be a user name with email address of the form `Mary Smith <m.smith@example.org>`.
   *  Some interfaces allow comma-delimited lists to be split into separate
      entries automatically to better support copy/paste functionality for
      populating members.

## Using Groups

*  **Resource Policy**: If you are adminstrating a Data Access Manager (DAM),
   you may specify a policy of `allowlist` and populate one or more group names
   in the `groups` variable to complete the policy.

## Modifying Groups

Only a system administrator is able to modify a group.

## Remove a Group

Only a system administrator is able to modify a group. This can only be done
if there are no policies or permissions using the group.
