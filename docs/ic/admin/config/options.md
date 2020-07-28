# Option Configuration

## Overview

Options configured here affect the way the Identity Concentrator (IC) behaves.
Most options are enforced per [Realm](../../shared/admin/concepts.md#realms)
unless indicated otherwise.

## Master Realm Options

These options only take affect on the `master` Realm and are ignored on any
other Realm.

1. **Read-Only Master Realm**: When set to `true`, the master realm
   configuration becomes read-only and updates to the configuration must be
   performed via updating a config file.

## Options Available on All Realms

1. **Claim TTL Cap**: A maximum duration of how long individual visa claim
   entries can be cached and used before requiring them to be refreshed from the
   authority issuing the claim.
   *  Any Visas that have an `asserted` date longer than this TTL upper bound
      in the past will be filtered out of Passports when the Visa list is
      generated.
   *  Uses a duration format such `30d` (30 days) or `2h` (2 hours).
