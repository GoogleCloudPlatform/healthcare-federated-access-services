# Federated Access Documentation

## Quick-start Links

1. **[Solution](overview/solution.md#federated-access-solution)**: Introduce the
   benefits of cloud computing, the challenges of "federation" of identities and
   environments, as well as explain how components in this repository overcome
   those challenges.

1. **[Account Management](shared/account/README.md#user-account-management)**:
   description of user account provided across these components.

## Documentation by Role

1. **Users**:
   *  **[Account Management](shared/account/README.md#user-account-management)**:
      description of user account provided across these components.

1. **Administrators**:
   *  **[Identity Concentrator Admin](ic/admin/README.md#identity-concentrator-administration)**:
      how to administrate the Passport Broker.
   *  **[Data Access Manager Admin](dam/admin/README.md#data-access-manager-administration)**:
      how to administrate the Passport Clearinghouse.
   *  **[Playground](playground/README.md#federated-access-playground)**:
      describes a playground environment and provides links for how to set one
      up.

1. **System Developers and Integrators**:
   * **[Identity Concentrator Dev](ic/dev/README.md)**: technical
     information about the internal workings of the Identity Concentrator and
     its APIs.
   * **[Data Access Manager Dev](dam/dev/README.md)**: technical
     information about the internal workings of the Data Access Manager and
     its APIs.
   * **[Cross-Component Dev](shared/dev/README.md)**: technical information
     for how to combine multiple components.

## Categories of Documentation

Federated Access documentation is organized as follows:

1. **[Overview](overview/README.md#overview-of-federated-access)**: An
   understanding of the problem and solution space for Federated Access.

1. **[Playground](playground/README.md#federated-access-playground)**: How to
   set up a test or tutorial environment and interact with these systems using
   GA4GH Passports and Visas.

1. **[Identity Concentrator](ic/README.md#identity-concentrator)** (IC): Develop
   an understanding of the Passport Broker component included in this
   repository.

1. **[Data Access Manager](dam/README.md#data-access-manager)** (DAM): Develop
   an understanding of the Passport Clearinghouse component included in this
   respository.

1. **[Shared Documentation](shared/README.md#shared-documentation)**:
   Documentation that is shared between the IC and the DAM as they have some
   functionality in common.

## GA4GH Links

1. **Open Standards** used by these components:
   *  **[GA4GH Passports](https://bit.ly/ga4gh-passport-v1)**: The format of
      identity and authorization information as GA4GH Passports and GA4GH Visas.
   *  **[GA4GH AAI](https://bit.ly/ga4gh-aai-profile)**: The token mechanisms
      employed by Passports and Visas as a particular flavor of OIDC.
      *  **[OIDC](https://bit.ly/oidc-spec-v1)** (OpenID Connect): The
         underlying discovery and claim specification used by Passports.
      *  **[OAuth 2.0](https://bit.ly/oauth-spec-v2)**: The token layer
         leveraged by OIDC.
      *  **[JWT](https://bit.ly/jwt-spec-draft)**: The generic JSON Web Token
         (JWT) format that GA4GH AAI specifies for use with GA4GH tokens, and
         thereby this format spec governs Passports and Visas.

1. **Webinars** that provide background about Passports:
   *  **[GA4GH Passports Webinar 1](https://bit.ly/ga4gh-passports-webinar)**:
      Benefits of Integrating Global Electronic ID for Accessing Biomedical Data
      ([slides](https://bit.ly/ga4gh-passports-slides1)).
   *  **[GA4GH Passports Webinar 2](https://bit.ly/ga4gh-passports-webinar2)**:
      Implementing GA4GH Passports & AAI Technical Deep Dive
      ([slides](https://bit.ly/ga4gh-passports-slides2)).
