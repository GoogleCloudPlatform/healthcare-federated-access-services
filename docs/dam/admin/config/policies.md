# Access Policy Configuration

## Overview

Access policies define requirements and conditions necessary to met in order
to allow access to [resources](resources.md). These access policies are designed
to be written and then reused across multiple datasets or other services.
However, simple policies can also be written when reuse and managing large sets
of policies is not a concern.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/policy_enforcement_intro.png" width="1000px">

This section will be discussing the **Enforce Access** mechanism provided by
the Data Access Manager (DAM).

## Introduction to Policies

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/access_policy_evaluation.svg" width="1000px">

Policies place requirements on Passport Visa fields in order to met access
requirements for one or more [resources](resources.md) configured in the DAM.
The DAM takes care of enforcing several basic [visa
fields](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa-fields),
such as visa expiry, leaving [four main fields](#visa-field-requirements) for
policies to add data or service access requirements.

*  A policy `Visa Requirement` will instruct DAM's policy engine to find **one**
   valid visa that meets all four `Visa Field Requirements`.
*  If the DAM cannot find a valid visa that fully matches a Visa Requirement, or
   if the issuer is not trusted, the request for access will be denied.
*  Policies can contain multiple Visa Requirements that all must be met via
   various visas within the same passport.
   *  **Example**: a policy with requirements for 2 visas (i.e. "has 2 Visa
      Requirements") could be drafted to require that a researcher has
      `Bona Fide` status on one visa **AND** must have proof of signing off on a
      `Confidentiality Agreement` on another visa.
*  Policies can also encode more than one combination of requirements as
   "alternative scenarios" to meet the policy.
   *  See the [Example with Multiple Requirement
      Scenarios](#example-with-multiple-requirement-scenarios).
   *  If multiple requirement scenarios are defined, the user must match at
      least one scenario but could match more than one and still get access.

### Visa Field Requirements

1. **Visa Type**: Represents the meaning of what the visa is asserting, as well
   as specifying how policies are to interpret the `value` field of the visa.
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
      *  In this case, the visa issuer is `https://elixir.org`, representing
         Elixir AAI, whereas the `source` in the visa is something like
         `https://example.org`, representing "Institution A".
   *  When institutions issue their own visas, not just provide out-of-band data
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
   *  See the [GA4GH Passport "By" Field
   Definition](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#by)
      to understand the meaning of each role.

1. **Value**: A string that represents any of the scope, process, identifier and
   version of the assertion.
   *  The format of the string can vary by the Passport Visa Type.
   *  In general, this field represents the "**what**" of the visa assertion.
      *  **AffilationAndRole** visa type: `value` is "what role and affiliation".
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

## Visa Types

The visa types available for policies is defined in the [Visa Types
Configuration](visa-types.md) settings. If you need a custom visa type or if
standard visa types were not already populated for you, then you will need
to configure the needed visa type there first and then return to setting up
your policy afterwards.

## Blank Fields

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

## Simple Policy Example

To consider a simple policy, assume that there is only qualification needed to
meet the requirements of the policy. For example, perhaps a [Trusted Source
Organization](sources.md) is to issue a [Controlled Access Grant
Visa](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#controlledaccessgrants)
with a `value` of `http://trusted.example.org/visas/dataset500`.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/simple_policy.svg" width="500px">

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
   *  For this example, the policy's `source` field could be set to
      `https://dac.example.org` to only accept visas from this one source
      organization for this particular dataset.

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

## Example with Multiple Requirement Scenarios

Policies allow for a more complex set of requirements. Sometimes there is more
than one way to meet the requirements for access, or perhaps there is more than
one visa that will be required in order to capture external dependencies between
organizations.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/complex_policy.svg" width="1000px">

This example policy indicates that there are two separate scenarios to meet the
requirements for access:

1. Scenario 1: **Be approved for this dataset by a DAC** and **Agree to ethical
   conditions**.
   *  This Requirement Scenario will be used by "external" researchers for
      secondary use.

1. Scenario 2: **Be a biomedical researcher at example.org**.
   *  This Requirement Scenario will be used by "internal" researchers that
      maintain the dataset.

Of course real-world scenarios will need to be more careful about which internal
researchers have access, however this is just an example of having multiple
Requirement Scenarios as well as having at a Scenario with 2 visas required.
*  Scenario 1 requires a ControlledAccessGrants visa ("Visa Requirement 1A").
*  Scenario 1 also requires an AcceptedTermsAndPolicies visa ("Visa Requirement
   1B").

## Visa Conditions

Visas themselves have the ability to require additional visas to satisfy
"conditions" of use that are beyond this control of any one organization.
*  Visas have a field called "[conditions](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#conditions)"
   that inform policy enforcement engines to automatically require additional
   visas.
*  These additional requirements are **not** encoded into DAM policies, but are
   up to the issuers of the visas to decide what additional requirements they
   have and must be enforced in order to apply that visa to a policy.
*  The DAM will automatically add these additional requirements when attempting
   to use a visa that includes one or more `conditions`.

## Combining Identities

When any [policy scenario](#example-with-multiple-requirement-scenarios)
requires more than one visa, it is possible that the user has made use of
multiple identities to collect these multiple Visa Requirements.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/combining_identities.png" width="1000px">

In the example above, Registered Access has two Visa Requirements, and the
user has provided two visas that meet these requirements. However, each of these
visas came from different identities.
*  The user had signed into their `issuer_1` account to include their
   `bona_fide_researcher` visa (details not shown).
*  The user had signed into their `issuer_2` account to include their
   `ethics_code_of_conduct` visa (details not shown).
*  The Passport Broker -- such as an IC -- that originally created the Passport
   that contains these two visas would have also added an additional
   `LinkedIdentities` visa to the same Passport.
*  The `LinkedIdentities` visa asserts that "I, as the Passport Broker, do
   declare that this user has signed into these accounts as proof of ownership
   of these identities" and include some additional details about the account
   origins and timestamps of most recent evidence.

In order to use two or more visas that come from different identities, the DAM
policy enforcement engine must also add a requirement that there is a
`LinkedIdentities` visa from a Trusted Source and Issuer that includes these
two identities.
*  The Passport Broker will be the `issuer` of the `LinkedIdentities` visa, so
   to accept this visa the Passport Broker must be included in the [Trusted
   Issuers](issuers.md) list. Otherwise, the LinkedIdentities visa will be
   rejected.
   *  When the DAM works directly with the Passport Broker that issues
      `LinkedIdentities`, there will already be a Trusted Issuers entry for the
      Broker in order to fetch the Passport.
   *  In other cases, Passport Brokers talk to other Passport Brokers and pass
      visas along in the "chain of brokers" until they arrive at the DAM. In
      this case, the Passport Broker that issued the `LinkedIdentities` may not
      already be included in the DAM's Trusted Issuers list.
      *  Only a Trusted Visa Issuer entry needs to be made for this "more
         distant" Broker, so no need to fill in optional details about the OIDC
         endpoints such as Token and Authentication URLs.
      *  Only the required fields, and perhaps a Visa Translator, needs to be
         completed when wanting to accept Visas from Visa Issuers.
*  Once the DAM's policy enforcement engine finds a `LinkedIdentities` visa
   that is trusted for visas that would otherwise have met all the various
   requirements, it can accept the Requirement Scenario and therefore grant
   access to the requested resource.

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

1. Consider the [Simple Policy Example](#simple-policy-example) above. If there
   were 250 datasets to onboard, you would need to specify 250 policies since
   each one would need a unique `value` field representing the dataset.
   Moreover, it is harder to ensure that policies are maintained consistently
   over time when changes occur. To avoid this:
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
