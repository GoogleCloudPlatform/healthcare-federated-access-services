# Trusted Sources Configuration

## Overview

Trusted Sources are a set of sources of authority that the DAM can be configured
to trust within its policies. Sources of authority may be different from
Passport and Visa issuers, however it is also possible that some string values
are the shared between these two concepts.

To understand the difference between Trusted Sources and Trusted Issuers, please
consult the [Visa Field Requirements](policies.md#visa-field-requirements)
description details for **Source**.

## Trusted Source Lists

DAM offers the ability to keep multiple, separate lists of trusted sources. This
allows different policies to use a specific set of trusted sources that it will
accept.
*  For example, you could create one set of Trusted Sources called "Academic
   Institutions" and another set of Trusted Sources for "Collaboration
   Instititions".
   *  "Academic Institutions" could include all academic institutions that your
      DAM needs to recognize across all of its resources and policies.
   *  "Collaboration Institutions" could include a subset of institutions
      academic institutions that you have shared projects with, and also include
      some additional non-academic institutions that you colaborate with as
      well.
   *  Some policies may be configured to offer `read` file permission to
      researchers that provide visas with a `source` field from any of the
      organizations in the "Academic Institutions" list.
   *  Other policies may be configured to offer `read and write` file permission
      to researchers with a visa `source` from "Collaboration Institutions".
   *  Some institutions may be on both lists.
*  It is best practice to create Trusted Sources lists instead of repeating
   the same list of `source` URLs across multiple policies.
   *  It is easier to maintain if stored in a central list.
   *  It is easier to ensure correctness and consistency between policies.
   *  The policy's intent will be easier to understand when reading the Trusted
      Source list name in the policy than it would be by listing a bunch of
      URLs.

## Impact on Test Personas

Adding or removing entries from a Trusted Issuers list could impact which
[Test Personas](personas.md) will receive access. When editing Trusted Issuers
lists, you will receive a warning when Test Personas are impacted, and prompted
to have the new set of expected access lists per Test Persona updated before
saving changes to the Trusted Issuers.
