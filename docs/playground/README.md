# Federated Access Playground

## Overview

A Federated Access Playground creates a simulation environment where users of
the playground can conduct tests and complete tutorials without the need to
integrate with production Passport providers.

> **IMPORTANT:** Never provide real production data, such as any data containing
> PII or PHI, to a Playground environment. Playgrounds are for
> **test and synthetic data only**.

This section will discuss what a Playground environment is, how it works, and
how to create one of your own.

## Playground Configuration

A Playground uses the same Identity Concentrator (IC) and Data Access Manager
(DAM) binaries as would a production environment, however it configures them
to trust and use a Playground-specific **Persona Broker** as follows:

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/playground_flow.svg" width="800px">

1. **Test Personas DAM Configuration File**: The Persona Broker is provided a
   set of Test Personas that are used for sign-in purposes. These Test Personas
   are made-up users that contain standard OIDC claims such as names and email
   addresses, along with GA4GH Passport Visa Assertions.
   *  The configuration file containing the Test Personas is deployed in the
      same container as the Persona Broker.
   *  You can make up details about the users and the visas they possess to test
      out a variety of circumstances.
   *  You redeploy the Persona Broker every time you change the configuration
      file.
   *  The default playground comes with some Test Personas predefined. Of
      special significance are:
      *  **Administrator**: Doesn't have any Passport Visas, but the default
         Playground IC and default Playground DAM are configured to treat this
         account (`admin@nci.nih.gov`) as a system administrator for both
         systems.
      *  **NCI Researcher**: Has useful Visas that the default Playground DAM
         has been configured to accept to get access to the default GCS Bucket
         based on the policy it comes with.

1. **Persona Broker**: This playground-only component lets any person using it
   sign-in without a password to **any** Test Persona it is configured (in the
   previous step) to provide.
   *  Everyone can impersonate the `Administrator`, or `NCI Researcher`, or any
      other roles that policies get configured to accept.
   *  The Persona Broker will read the file from `#1` and offer the list of
      personas to the user to choose from. This makes it easy to know what
      accounts are available via a Persona Broker.
   *  Since the Test Persona config file doesn't have signatures on the Visa
      Assertions, it is the Persona Broker that will sign all the Visas that it
      provides in its Passport.
      *  This implies that the playground DAM must be configured to accept the
         Persona Broker as a Trusted Issuer of Visas in order to have the
         playground work.

1. **Identity Concentrator**: This is a stock Identity Concentrator that has
   been configured to use the Persona Broker as its [Identity
   Provider](../ic/admin/config/identity-providers.md).
   *  The IC will collect the Visas from the Passport provided from the Persona
      Broker, open accounts for each Test Persona as if they were real users,
      and provide these Visas to the DAM.
   *  Notice that the IC is unaware that these are Test Personas.
      *  Its trust of the Persona Broker to provide identities and visas is
         sufficient for the IC to provide the necessary "IC" functionality for
         the playground environment.
      *  No special functionality is needed within the IC for playgrounds as it
         is just a matter of how the IC is configured to make this work.

1. **Data Access Manager**: This is a stock DAM that has been configured to use
   the Persona Broker as a [Trusted Visa
   Issuer](../dam/admin/config/issuers.md).
   *  The default playground DAM has
      [policies](../dam/admin/config/policies.md) as well as
      [resources](../dam/admin/config/resources.md) configured sufficient for
      the `NCI Researcher` Test Persona to get access to a test GCS Bucket that
      gets created as part of setting up the Playground environment.
   *  The default playground DAM is also configured to have at least two
      [Trusted Issuers](../dam/admin/config/issuers.md):
      *  Use and accept Passports coming from the playground IC from `#3` above.
      *  Accept Visas signed by the Persona Broker.
   *  Notice that the DAM is unaware that these are Test Persona identities.
      *  The accounts come from upstream sources, not part of its configuration.
      *  Treat the DAM's own Test Personas as potentially different. Recall that
         the identities that DAM receives are ultimately from the Persona Broker
         (via the IC) and may be a completely different set of Test Personas
         than what exist in the DAM.
      *  The playground works with a stock DAM just through its Trust
         Configuration to be using a playground-only Persona Broker and a
         playground-configured IC.

1. **Cloud and On-Prem Services**: Stock services may be used, such as real
   cloud services, however **only test or synthetic data should ever be exposed
   via a playground environment**.
   *  Buckets and Tables should be test data, for example.
   *  Remember that anyone coming to the playground can act as the
      `Administrator` and change any clever settings that may be used to not
      expose the underlying data. **So treat all data as fully public**.
   *  Always use a separate account or project on cloud systems specifically for
      playgrounds to provide the **necessary** isolation of scope of what data
      may get exposed.
   *  The default playground configuration provides a test GCS Bucket with
      test-only data in it.

This configuration simulates real-world
[solutions](../overview/solution.md#solution)

## Playground Components

In addition to the Persona Broker discussed above, there are two additional
Playground Components provided by the default playground environment.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/playground_components.svg" width="500px">

1. **IC Demo**: Provides a means to sign-in using the Persona Broker to create
   a user account in the IC, create a Passport, and inspect account and Passport
   contents.
   *  See the [IC Demo instructions](ic-demo.md) for details.

1. **DAM Demo**: Provides a means to request resources from DAM, sign-in using
   the Persona Broker, receive an IC Passport containing those Persona Broker
   Visas, and apply them to access policies in the DAM to get cloud-level
   access to a GCS bucket.
   *  See the [DAM Demo instructions](dam-demo.md) for details.

Note that production systems will not be deployed with an IC Demo, DAM Demo, nor
a Persona Broker. For more information about production-ready systems, please
consult [Productionization Best
Practices](../shared/admin/productionization.md)

## Deploying a Playground

Read the [Playground Deployment](deploy.md) documentation when ready to create
your own playground environment.

To help with changing playground-related settings, such as Persona Broker Test
Personas, see the [Playground Settings](settings.md) page.

## Other Playground Configurations

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/all_playground_components.svg" width="950px">

The Persona Broker may also be deployed in a system with more components to
simulate a full end-to-end system.

1. **[DDAP Explorer](https://github.com/DNAstack/ddap-explore)**: Offers a
   front-end to explore and get access to data for the purposes of executing
   workflows on cloud.
   *  This can be be done by having data access policies be met by impersonating
      Test Personas and using their visas to simulate getting access for running
      compute jobs.

1. **[IC Management Console](https://github.com/DNAstack/ddap-ic-admin)**: A
   User Interface for end users and system administrators of the Identity
   Concentrator.
   *  Users may manage their accounts for the IC.
   *  Administrators may manage the IC configuration options as well as
      provide user support and system auditing.

1. **[DAM Management Console](https://github.com/DNAstack/ddap-dam-admin)**: A
   User Interface for end users and system administrators of the Data Access
   Manager.
   *  Users may manage their accounts for the DAM.
   *  Administrators may manage the configuration options of the DAM as well as
      provide user support and system auditing.

See the GitHub repo links above for more information about these components and
how to deploy them into your playground environment.
