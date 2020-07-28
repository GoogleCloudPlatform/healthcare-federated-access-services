# Visa & Passport Issuer Configuration

## Overview

Passport and Visa Issuers are services that create signed JWT tokens for use
by the Data Access Manager (DAM) when evaluating whether or not a user meets
the access policy requirements for the resources they have requested.

## Passports and Visas

*  **Passport**: this is an access token the user recieves upon signing in to
   a GA4GH Passport-compliant authentication service as per the [GA4GH Passport
   specification](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#overview).
   *  A user may only use one passport at a time that represents their digital
      identity to the systems they interact with.
   *  Passport contents may be merged from multiple sources and presented as a
      single passport.
   *  Passports always include an issuer URL claim (known as `iss`) as part of
      the Passport to indicate which service created it.
   *  Each passport is digitally signed using cryptographic-strength algorithms.
   *  Each service that creates Passport tokens uses its own private key to sign
      the Passport token that can be verified by the DAM for authenticity.

*  **Visa**: each passport may provide a set of `visas`. Each visa represents
   a general user qualification or permission a specified resource.
   *  Resources are general terms that may include: a specific piece of data,
      a named list of files or tables, an entire named dataset, a service, or
      a set of services, etc.
   *  [Custom Visas](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#custom-passport-visa-types)
      may even support providing lists of resources, such as having one Visa
      that can provide permission to multiple specific datasets.
   *  Much like Passport tokens, Visas always include an issuer URL claim
      (known as `iss`) as part of the Visa to indicate which service created it.
   *  Each Visa is digitally signed using cryptographic-strength algorithms
      which is used by the DAM to determine authenticity.
   *  See the [Visa Types documentation](visa-types.md) to learn more about
      different standard types of Visas that DAMs can be configured to use.

## Network of Passport and Visa Issuers

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/passport_map.svg" width="1000px">

There are more Passport and Visa issuers joining a global community of providers
of these services. It is important to establish trust, formalized via
organizational policies, to provide identity and qualification information to
a DAM to evaluate against [access policies](policies.md).

A DAM will reject Passports and Visas from issuers that are not explicitly
listed within its Trusted Issuers configuration. These tokens will never even
make it to policy evaluation as part of a resource access request if they are
not included in the allowable list of token issuers.

## Trusted Issuers

Add one Trusted Issuer entry for each Passport and Visa Issuer that will be used
in any policy used by a particular DAM instance.

1. **Client Registration**: Many Issuers will need to have a client registration
   performed before the DAM is able to make use of the issuer to collect tokens
   and verify signatures.
   *  **Client Identifier**: a unique identifier, often an abstract string such
      as a GUID, that represents the DAM on within the Issuer's system.
   *  **Client Secret**: an opaque string that is stored by the DAM that should
      only be known by the DAM and the Issuer. This should be safeguarded such
      that no other person or service can use it to impersonate the DAM.

1. **Passport Issuer Additional Fields**: Passport Issuers need additional
   information in order to sign-in users and acquire Passport access tokens.
   The values DAM needs can be found from the OIDC Discovery service's
   `.well-known` endpoint by taking the `Issuer URL` and adding
   `/.well-known/openid-configuration` to the end.
   *  **Auth URL**: Discovery name is `authorization_endpoint`. A URL that
      points to the Passport Issuer's authentication (sign-in) endpoint.
   *  **Token URL**: Discovery name is `token_endpoint`. A URL that points to
      the Passport Issuer's token creation endpoint.

1. **Visa Translation**: Some services do not provide standard visas and DAM
   need to translate the data within these custom visas into standard form such
   that it can process it.
   *  For example, DAM provides a `dbGaP Passport Translator` to translate
      Passports and Visas issued by NIH's dbGaP system into GA4GH standard visa
      format.
