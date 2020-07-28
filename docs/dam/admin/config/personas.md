# Test Persona Configuration

## Overview

Test Personas provide a mechanism to verify how policies will behave when users
request access to particular resources. Whenever policy or resource definitions
change, the Data Access Manager (DAM) will validate that the access list of each
persona remains the same as before, or will prompt the administrator to resolve
any test persona access changes that are a result of pending configuration
changes.

For a better understanding of how Test Personas work, please consult with
documentation for [Data Resources](resources.md) and [Data Access
Policies](policies.md) to provide the context needed for the remainder of this
page.

## Test Persona Purpose

Consider the following scenario:

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/access_policy_evaluation.svg" width="1000px">

When authoring a policy, several questions come to mind:

1. How do I know when a policy is correctly formatted to allow access to a set
   of users that have the appropriate visas attached to their passports?
1. How do I know when a policy is correctly formatted to **deny** access to
   users when various requirements are not met?
1. How can I ensure that I am confident that changes to my configuration -- such
   as general setting options, trusted issuers and sources, as well as policy
   updates -- will not accidently impact my expectations about who should and
   should not have access to each of my datasets?

Test Personas are designed to bring confidence that policies and resources are
set up correctly, and that changes to the system have well understood impacts
by "testing" how each Test Persona's access will be impacted before committing
changes to the configuration.

Note that the DAM does not not actually issue real passports and visas for these
test personas. It only simulates "what would happen if a user with a passport
like this test persona arrives and asks for each role of each resource across
the system".

With a set of Test Personas, you end up with test results that can be
represented as a table like this:

| Test Persona   | Resource A: Bucket Viewer | Resource A: Table Viewer | Resource B: WES Execute |
| -------------- | ------------------------- | ------------------------ | ----------------------- |
| Persona Bill   | **YES**                   | **YES**                  | no                      |
| NCI Researcher | **YES**                   | no                       | **YES**                 |
| ...            | ...                       | ...                      | ...                     |

More test personas, each with a different set of visas, or visas with slightly
different visa field settings, will provide more test coverage.

## Test Persona Claims

There are two types of claims that users bring with them as part of their
authentication and authorization flows that the DAM uses when evaluating access
policies:

1. **Standard Claims**: These are standard JWT claims that exist on JWT access
   tokens. There can be quite a number of such claims, but since most of these
   are not used in access policies, only a couple standard claims matter:
   *  **Issuer URL**: This is the OIDC issuer URL string pointing to the OIDC
      service that generated the access token.
      *  This is used as part of Trusted Visa Issuer evaluation to see if the
         issuer is trusted.
      *  Changes to the [trusted issuers](issuers.md) will impact acceptance
         of the access token in general.
   *  **Email**: This is the OIDC `email` claim as part of [OIDC standard
      claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims).
      *  This may be used as part of the `allowlist` policy if the issuer string
         (i.e. "iss" claim value) is a trusted source.

1. **Passport Visas**: These are [GA4GH Passport
   Visas](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa)
   that can be evaluated as part of various policies configured within a DAM.
   *  Four of the fields (`visa type`, `source`, `by`, and `value`) are
      configured as [Visa Field
      Requirements](policies.md#visa-field-requirements).
   *  `Asserted Duration`: how long ago in the past was this test persona's visa
      [asserted](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#asserted).
      *  Instead of being a fixed timestamp, it is specified as a duration into
         the past such that these visas don't return a different expiry status
         depending on when the test personas evaluation is done.
      *  The format is a duration such as `30d` for "asserted 30 days ago", or
         `2h` for "asserted two hours ago".
      *  When evaluating access of test personas, the `asserted` field is
         calculated as:
         ```
         now() - assertedDuration
         ```
   *  `Expires Duration`: how long into the future does the visa expire.
      *  Format is similar to `Asserted Duration`, however for this field the
         value represents a duration into the future.
      *  This field determines the [visa's
         expiry](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa-expiry).
      *  When evaluating access of test personas, the visa's `exp` claim is
         calculated as:
         ```
         now() + expiresDuration
         ```

## Adding Test Personas

Best practice would be to:

1. **Confirm Access Granted**: Add a number of test personas to provide coverage
   of the various types of visas you expect your system to receive as part of
   the datasets and services that the DAM provides access to.

1. **Confirm Permission Denied**: Add test personas with a set of visas that
   test that your policies are checking all the appropriate fields and reject
   test personas to datasets.

When adding Test Personas, there will be a table of all the roles published for
every resource configured by the DAM. Check the box for each resource the new
Test Persona should have access to, and leave the checkbox unchecked if it
should not have access.

*  When saving the Test Persona, the DAM will confirm your settings and produce
   an error if your access chart does not match its test results.
*  If you agree with the test results, change the checkboxes accordingly and
   try to save the Test Persona again.
*  If you do believe the test results have highlighted a problem, explore the
   policy and resource configurations on other tabs to determine why the Test
   Persona has access to those specific resources, and save any configuration
   changes you make to fix the problem. Then return to the new Test Persona page
   and try again to save it.

## Using Test Personas

Whenever a configuration change is requested that may affect access to
resources, the DAM will automatically calculate the Test Personas access chart
and return errors if they don't match the expected access list configured for
the Test Personas. You will need to fix the expected access list for the Test
Personas tht are impacted as part of submitting your configuration change.
