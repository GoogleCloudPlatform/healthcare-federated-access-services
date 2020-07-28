# Visa Type Configuration

## Overview

Visa Types determine the semantic meaning of the [value
field](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#value)
within a Passport Visa.

A Data Access Manager (DAM) is configured to recognize a particular set of
standard Visa Types as well as any [Custom Visa
Types](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#custom-passport-visa-types) that your particular policies may make use of. The DAM will not allow
other parts of the configuration refer to Visa Types unless they are first
defined in the available Visa Types section of the DAM configuration.

## Standard Visa Types

When installing a new DAM using the default DAM configuration template, all five
[GA4GH Standard Passport Visa
Types](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#ga4gh-standard-passport-visa-type-definitions)
in `v1.0` of the Passport Specification are included in the configuration.

These include:

1. **[AffiliationAndRole](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#affiliationandrole)**:
   Asserts that a user has a particular role within a given institution.

   For example:
   ```
   {
       "sub": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx@elixir-europe.org",
       "ga4gh_visa_v1": {
           "asserted": 1595643749,
           "by": "system",
           "source": "https://login.elixir-czech.org/example-idp/",
           "type": "AffiliationAndRole",
           "value": "affiliate@example.org"
       },
       "iss": "https://login.elixir-czech.org/oidc/",
       "exp": 1627179749,
       "iat": 1595643750,
       "jti": "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
   }
   ```

   The above example visa asserts that the user is an `affiliate` at the
   organization represented by `example.org`. Note that `affiliate` is defined
   by [eduPersonAffiliation](https://wiki.refeds.org/display/STAN/eduPerson+2020-01#eduPerson2020-01-eduPersonAffiliation)
   could be a "volunteer", and hence a policy in DAM looking for a specific role
   related to research would likely **not** want to accept values like this
   one.

   See [AffiliationAndRole notes from the GA4GH website](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#affiliationandrole).

1. **[AcceptedTermsAndPolicies](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#acceptedtermsandpolicies)**:
   The user and/or the user's home organization has acknowledged the specific
   terms, policies, and conditions (or meet particular criteria) as indicated by
   the `value` field within the Visa.

   The `value` field is a URL identifier for the contract, agreement, or policy
   that has been acknowledged or agreed to.

   See [AcceptedTermsAndPolicies notes from the GA4GH
   website](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#acceptedtermsandpolicies)
   as well as [notes on visas for use with Registered
   Access](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#claims-use-for-registered-access)
   for more information and examples.

1. **[ResearcherStatus](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#researcherstatus)**:
   The person has been acknowledged to be a researcher of a particular type or
   standard.

   The `value` field is a URL identifier for the researcher status standard.

   See [ResearcherStatus notes from the GA4GH website](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#researcherstatus) as well as [notes on
   visas for use with Registered Access](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#claims-use-for-registered-access)
   for more information and examples.

1. **[ControlledAccessGrants](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#controlledaccessgrants)**:
   Represents that a dataset, service, or other object for which controlled
   access has been granted to this user.

   The `value` field is a URL identifier for the controlled access item that it
   is asserting on behalf of.

   See [ControlledAccessGrants notes from the GA4GH website](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#controlledaccessgrants)
   for more information and examples.

1. **[LinkedIdentities](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#linkedidentities)**:
   It asserts that the identity (i.e. the account) of the Passport Visa is the
   same as the identity or identities listed in the `value` field.

   See [LinkedIdentities notes from the GA4GH website](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#linkedidentities) as well as [notes on
   visas for use with Registered Access](https://github.com/ga4gh-duri/ga4gh-duri.github.io/tree/master/researcher_ids#claims-use-for-registered-access)
   for more information and examples.

## Custom Visa Types

If systems generating Passport Visas are not able to represent their assertions
or attestations within one of the [GA4GH Standard Visa
Types](#standard-visa-types), they may opt to create their own [Custom Visa
Type](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#custom-passport-visa-types).
*  Some Custom Visa Types simply define their own opaque string identifier
   format or semantics within the existing [standard visa fields as supported
   by the DAM's policy engine](policies.md#policy-condition-fields).
*  Other Custom Visa Types may go outside of the set of known fields or
   semantics supported by the DAM's policy engine.
   *  DAM offers a Visa Issuer Translation plug-in that can put specific
      non-standard custom visa formats into the standard fields. This requires
      custom code, and is not always possible depending on the semantics of
      the custom visa's descriptors and metadata.
   *  As new Custom Visa Types are invented that DAM does not support, you are
      encouraged to file an issue on this GitHub repository to discuss if it is
      feasible to write a Visa Issuer Translation plug-in to support it.
*  Please consult the [GA4GH Custom Passport Visa
   Registry](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_custom_visas.md)
   for details about known Custom Visa Types.
*  If services within your environment generate new Custom Visa Types, and
   those Visas are destined for a federated production environment, please
   reach out to GA4GH to register your new Visa Type as per the [Custom Visa
   Type specification](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#custom-passport-visa-types).
