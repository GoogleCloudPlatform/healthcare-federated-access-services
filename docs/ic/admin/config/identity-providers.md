# Identity Provider Configuration

## Overview

Identity Providers are services that create signed JWT tokens for use
by the Identity Concentrator (IC) when signing in a user. The IC supports
any standard OpenID Connect (OIDC) identity provider, but also has special
support for [GA4GH Passport
Brokers](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-broker)
by managing sets of [GA4GH Passport
Visas](https://github.com/ga4gh-duri/ga4gh-duri.github.io/blob/master/researcher_ids/ga4gh_passport_v1.md#passport-visa)
that they provide.

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
      the Passport token that can be verified by the IC for authenticity.

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
      which is used by the IC to determine authenticity.

## Network of Passport and Visa Issuers

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/passport_map.svg" width="1000px">

There are more Passport and Visa issuers joining a global community of providers
of these services. It is important to establish trust, formalized via
organizational policies, such that identity and qualification information can be
collected by an IC and passed along to a [Data Access
Manager](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services#data-access-manager)
for [policy evaluation](../../../dam/admin/config/policies.md).

In addition to these, there are a large number of generic OIDC Identity
Providers that can authenticate the user. The IC can link accounts for users to
combine multiple identities and manage sets of Passport Visas and make them
available for a duration even when the user signs in with an account that does
not have these Visas attached under normal circumstances. [Options](options.md)
with the IC define the behavior that the IC will conform to in this regard.

## Identity Providers

Add one Identity Provider entry for each Passport Broker or other OIDC provider
that will be used by a particular IC instance.

1. **Client Registration**: Many Identity Providers will need to have a client
   registration performed before the IC is able to make use of the issuer to
   collect tokens and verify signatures.
   *  **Client Identifier**: a unique identifier, often an abstract string such
      as a GUID, that represents the IC on within the Identity Provider's
      system.
   *  **Client Secret**: an opaque string that is stored by the IC that should
      only be known by the IC and the Issuer. This should be safeguarded such
      that no other person or service can use it to impersonate the IC.

1. **Identity Provider Additional Fields**: Identity Providers need additional
   information in order to sign-in users and acquire access tokens.
   The values IC needs can be found from the OIDC Discovery service's
   `.well-known` endpoint by taking the `Issuer URL` and adding
   `/.well-known/openid-configuration` to the end.
   *  **Auth URL**: Discovery name is `authorization_endpoint`. A URL that
      points to the Identity Provider's authentication (sign-in) endpoint.
   *  **Token URL**: Discovery name is `token_endpoint`. A URL that points to
      the Identity Provider's token creation endpoint.

1. **Visa Translation**: Some services do not provide standard Passport Visas
   and the IC will need to translate the data within these custom visas into
   standard form such that it can process it.
   *  For example, the IC provides a `dbGaP Passport Translator` to translate
      Passports and Visas issued by NIH's dbGaP system into GA4GH standard visa
      format.
