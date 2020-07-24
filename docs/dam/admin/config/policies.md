# Access Policy Configuration

## Overview

Access policies define requirements and conditions neccessary to met in order
to allow access to [resources](resources.md). These access policies are designed
to be written and then reused across multiple datasets or other services.
However, simple policies can also be written when reuse and managing large sets
of policies is not a concern.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/policy_enforcement_intro.png" width="1000px">

This section will be discussing the **Enforce Access** mechanism provided by
the Data Access Manager (DAM).

## Simple Policies

To consider a simple policy, assume that there is only qualification needed to
meet the requirements of the policy. For example, perhaps a [Trusted Source
Organization](sources.md) is to issue a [Controlled Access Grant
Visa](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#controlledaccessgrants)
with a `value` of `http://trusted.example.org/visas/dataset500`.

1. For the simple case, you would not have to define any variables.

1. You would add a policy requirement and set the `value` of that condition
   to `https://trusted.example.org/visas/dataset500`.

1. You would specify the trusted source organization by adding a `source` string
   that represents the organization.
   *  This must match the [Visa Source
   URL](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#source)
   that is included in the Visa.
   *  This will be a canonical URL identifier for the source organization. This
      is only a unique URI, and does not get dereferenced at time of policy
      evaluation. It may resolve to a human readable web page for convenience of
      those configuring systems, but it doesn't have to and often is treated
      strictly as an opaque string identifier.
   *  Check with the [Visa
      Issuer](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa-issuer)
      you plan to use to see what string they will be using to identify the
      required source organization.

1. You probably don't want just anybody within that source organization able to
   issue this controlled access grant.
   *  GA4GH Passports provide a set of roles that act as the source of authority
      within an organization.
   *  For controlled access grants, this is usually a Data Access Committee
      (DAC).

1. Set the `by` field in your policy to `dac`. This will prevent self-issued
   assertions, for example. This restriction tells the policy engine that the
   trusted source organization must have a DAC assert that the user should be
   granted access.

For this simple policy example, we only need to fill in the 3 fields with one
string setting each on a single clause.

## Visa Types

The visa types available for policies is defined in the [Visa Types
Configuration](visa-types.md) settings. If you need a custom visa type or if
standard visa types were not already populated for you, then you will need
to configure the needed visa type there first and then return to setting up
your policy afterwards.

## Blank Fields and Multiple Clauses

1. Any fields within the policy that are left empty are interpreted as something
   that is left unenforced. Because the steps above set all three fields within
   the policy condition, all three must be met at the same time on the same
   Passport Visa.
   *  For example, there may be other visa types where `by` is not included, or
      less important. Therefore it is important to fill in all the requirements
      in the policy or these fields will not be enforced during policy
      evaluation.

1. Visas only have one string value given for each field. If your policy
   specifies more than one `by`, for example, it means that any value that is
   in the policy will be accepted. This is true for the `source` and `value`
   fields as well.

1. Policies can have more than one `clause`.
   *  When more than one clause is present, any one or more clauses that are
      met will be suffient to allow access.
   *  That is, clauses specify different sets of requirements that each by
      themselves is enough to achieve access when met.

## Managing Multiple Similar Policies

1. Repeating the same list of trusted sources across many policies is error
   prone and difficult to maintain. To avoid this:
   *  Using the [Trusted Sources](sources.md) configuration system, assign a
      list of trusted sources under a given `trusted sources name`.
   *  In your policies `source` field, specify the `trusted sources name`
      instead of a URL.
   *  Update the list of URLs included in your `trusted sources name` and all
      of your policies using this name will be updated consistently for you.
   *  The policy `source` field allows more than one setting. Use this to
      combine multple lists together.
      *  For example, set `source` to: `academic institutions`,
         `institutions of NIH`
      *  If the first list has 100 entries and the second has 27, then all 127
         institutions will be permitted to be the `source` for such a policy.

1. Consider the [Simple Policy](#simple-policies) example above. If there were
   250 datasets to onboard, you would need to specify 250 policies since each
   one would need a unique `value` field representing the dataset. Moreover,
   it is harder to ensure that policies are maintained consistently over time
   when changes occur. To avoid this:
   *  Use the policy `variable` feature to define one or more variables to
      include in your `value` field. For example, define `DATASET` as:
      *  Name: `DATASET`
      *  Description: `Dataset name (e.g. 'phs000710')`
      *  Regular Expression: `[a-z0-9]{6,9}`
   *  In the above example, the regular expression will check that dataset names
      that will be provided elsewhere when the policy is used must only contain
      lowercase letters 'a' through 'z' and numbers '0' through '9', and must be
      between 6 and 9 characters long.
   *  Substitute place where the dataset name would be within the `value` field
      of the policy with `${DATASET}`. This is how variables are specified
      within policies.
   *  When using policies as part of enabling [Roles on Resource
      Views](resources.md#role-based-access-policies), you will also provide
      values for all the variables you defined on the policy selected for each
      role.
      *  Role: Viewer
      *  Policy: My Dataset Policy
      *  Variables: `DATASET=phs000710`
   *  Notice that it is much easier onboard many datasets this way as the Data
      Custodian does not need to remember and accurately record the full `value`
      URL string. Only the dataset name needs to be provided.
   *  Any changes or corrections to identifiers are easy to migrate as there is
      one central policy that can handle many resource configurations.
   *  For example, add two `value` entries to migrate from one domain to another
      (then update the policy again to remove the older domain when it is no
      longer in use):
      *  Policy: My Dataset Policy
      *  Requirement Value: `https://trusted.example.org/visas/${DATASET}`,
         `https://updated.example.org/visas/${DATASET}`

1. If there are multiple possible `value` field settings that would all be
   acceptable, and they are too many to enumerate, then you may choose to use
   [GA4GH Pattern Matching](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#pattern-matching)
   within the settings you provide.
   *  Use the `?` character to match **any** one character.
   *  Use the `*` character to match **any** zero or more characters.
   *  **Important**: Carefully consider the impact of accepting these patterns
      to ensure that there are not cases of strings that will match that do not
      actually meet the intended requirements.

1. Combine policies together by listing more than one policy in a resource
   configuration.
   *  You may have multiple policies that make sense to enforce as "meets
      the requirements of ALL of the following policies": policy 1, policy 2,
      etc.
   *  When configuring a role on a resource view, list all of the policies that
      apply. All of these requirements must be met in order to gain access.
      (i.e. it is a logical `AND` of all of these policies during policy
      evaluation)
