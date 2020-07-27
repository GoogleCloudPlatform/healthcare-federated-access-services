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

## Introduction to Policies

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/access_policy_evaluation.png" width="1000px">

Policies place requirements on Passport Visa fields in order to met access
requirements for one or more [resources](resources.md) configured in the DAM.
The DAM takes care of enforcing several basic [visa
fields](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa-fields),
such as visa expiry, leaving [four main fields](#policy-condition-fields) for
policies to add data or service access requirements.

*  A policy condition will instruct DAM's policy engine to find **one** valid
   visa that meets all four field requirements.
*  If the DAM cannot find a valid visa that matches a policy condition, or if
   the issuer is not trusted, the request for access will be denied.
*  Policies can contain multiple conditions that all must be met via various
   visas within the same passport.
   *  **Example**: researcher must have `Bona Fide` status on one visa **AND**
      must have proof of signing off on a `Confidentiality Agreement` on another
      visa.
*  Policies can also encode more than one combination of conditions as
   "alternative" ways to meet the policy
   *  **Example**: researcher must meet **one** of the following sets of
      requirements:
      *  **Option A**: person must be researcher affiliated with `Institute A`.

      **OR**

      *  **Option B**: researcher must have `Bona Fide` status on one visa
         **AND** must have proof of signing off on a `Confidentiality Agreement`
         on another visa.

### Policy Condition Fields

1. **Visa Type**: Represents the meaning of what the visa is asserting, as well
   as specifying how policies are to interpet the `value` field of the visa.
   *  For example, an [AffilationAndRole Visa
      Type](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#affiliationandrole)
      expects a `value` format of `<role-name>@<affiliation-org-domain>` whereas
      a [ControlledAccessGrants Visa
      Type](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#controlledaccessgrants)
      expects a `value` to be a URI that uniquely identifies the resource
      (dataset, service, etc).
   *  See the [GA4GH Passport spec Visa Type
      definition](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa-type)
      for more details.
   *  See the [GA4GH Passport spec list of Standard Visa
      Types](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#ga4gh-standard-passport-visa-type-definitions).
   *  You may also define your own [Custom Visa
      Types](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#custom-passport-visa-types)
      and use them in your policies. However, you must first add them to the DAM
      using the [Visa Type Configuration](visa-types.md) settings.

1. **Source** (a.k.a. Source Organization Identifier): A URI that uniquely
   identifies the organization that made the visa assertion. This is the "source
   of authority" for the visa, which may be different in some cases from the
   issuer of the visa itself.
   *  For example:
      *  Elixir AAI may issue visas and thus be the issuer (i.e. the `iss`
         claim) for the visa as the infrastructure that has packaged up the visa
         and assures it is accurately represented.
      *  An institution on the EduGAIN network, call it "Institution A", may
         store information about the user and inform Elixir AAI about the role
         and affiliation of the user.
      *  In this case, the visa issuer is ``, representing Elixir AAI, whereas
         the `source` in the visa is something like ``, representing
         "Institution A".
   *  When instutitions issue their own visas, not just provide out-of-band data
      to another visa issuer service, then the issuer and the source may be the
      same URI string.
      *  However, it is also possible that the `source` may be a canonical
         identifier for the institution (which ideally does not change over
         time) whereas the "issuer" string is the specific software service that
         is being used at present, so institutions may opt to use a different
         `source` string than they use for the "issuer" string of the token.
      *  Therefore policies should not automatically assume that `source` and
         `issuer` are the same strings, even in cases where institutions issue
         their own visas. It is recommended that documentation is used to
         determine what the appropriate `source` string should be.

1. **By**: This is a GA4GH fixed-vocabulary role name for the person or system
   that is the source of the authorization within the `source` organization that
   is asserting the visa information.
   *  This field is optional on some visa types, and required on others.
   *  See the [GA4GH Passport By Field
   Definition](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#by)
      to understand the meaning of each role.

1. **Value**: A string that represents any of the scope, process, identifier and
   version of the assertion.
   *  The format of the string can vary by the Passport Visa Type.
   *  In general, this field represents the "**what**" of the visa assertion.
      *  **AffilationAndRole** visa type: `value` is "what role and affilation".
      *  **AcceptedTermsAndPolicies** visa type: `value` is "what document the
         user or organization acknowledged or agreed to".
      *  **ResearcherStatus** visa type: `value` is "what standard of researcher
         this user mets".
      *  **ControlledAccessGrants** visa type: `value` is "what service or
         dataset the user has been granted access to".
      *  **LinkedIdentities** visa type: `value` is "what other identities or
         email addresses the user is also known by".
   *  See examples under **Visa Type** entry above to better understand how the
      format of the value is to be interpreted based on visa type.

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

## Allowlist Policy

DAM supports an `allowlist` policy to directly add email addresses and group
names in leu of more specific Passport Visas. This policy is buit in to DAM
and does not require any editing of the policy as described above for other
policies.

Use cases:
1. This policy is particularly handy in pre-publication use cases because
   several researchers need to collaborate as part of building and curating a
   dataset and no Data Access Committee (DAC) to define and assert visas on
   behalf of this dataset while under development.
1. Once datasets are published for secondary use, such datasets may use DAM
   directly as part of the Data Access Committee approval by adding members to a
   group specific for a given dataset.
   *  Useful if the Data Controller does not already have other infrastructure
      to issue ControlledAccessGrants visas.
   *  Appropriate up to 1000 users being listed, if backups and DAM user and
      group import/export infrastructure is developed to ensure that disaster
      recovery does not lose the set of users allowed.

Details on how it works:
*  It provides a way to specify a set of users who should have access to a
   resource.
*  The policy exposes two variables that are populated as part of setting up a
   [role within a resource view](resources.md#role-based-access-policies):
   *  `users`: a set of user email addresses
   *  `groups`: a set of group names that each contain a set of user email
      addresses.
*  When using the policy within a role, you may specify one or both variables
   to make a combination of individual users as well as groups of users who
   should have access.
*  The policy makes use of the [Linked Identities
   visa](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#linkedidentities)
   to match user email addresses or determine group membership for the user.
*  This policy cannot be edited or removed.

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
