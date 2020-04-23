# `healthcare-federated-access-services` 

## Purpose

The Global Alliance for Genomics and Health ("GA4GH") has [launched](https://www.ga4gh.org/news/ga4gh-passports-and-the-authorization-and-authentication-infrastructure/) an open standard for requesting and granting access to genomic datasets, known as the "GA4GH Passport". This allows different identity providers and data hosts to interact with each other, independent of their hosting platform and identity provider. For example, the owner of a genomic dataset hosted on Google Cloud (e.g. a national genomics institute) can grant access to a researcher with an organizational identity (e.g. an academic or corporate email address) via a GA4GH passport.

The GA4GH Passport specification is a technology to eliminate barriers between users and data, even in complex multi-cloud and hybrid-cloud environments, while still adhering to data consents and strict sharing policies between the parties involved.

### Data Access Manager

This repository contains the Data Access Manager ("DAM"), which performs the role of a [GA4GH Passport Clearinghouse](http://bit.ly/ga4gh-passport-v1#passport-clearinghouse).

#### The problem

Sensitive data is often organized in controlled-access datasets where only qualified individuals or organizations should have access. Data controllers must identify these data accessors ahead of time, and then configure their datasets to permit access. This manual and error-prone process slows down collaboration and can make some use-cases impossible.

#### The solution

GA4GH Passports are a standard way to securely communicate information between data controllers and data accessors. The Data Access Manager (DAM) enables data controllers to seamlessly leverage GA4GH passports to make their data accessible, but also secure.

DAM enables the translation of abstract qualifications (e.g. I am a physician, I am an academic researcher, etc) into platform-specific access management configurations (e.g. I can access this file, I can run this operation). Once an administrator configures DAM with policies describing how qualifications should translate into data access (e.g. academic researchers should have access to files A and B, but not C), verification of those qualifications and the resulting reconfiguration of underlying permissions will occur automatically as data access requests are received.

DAM evaluates identities against policies in real-time, which means data controllers do not need to have a relationship with data accessors – in fact, data controllers and accessors do not need to know one another exist prior to a transaction. DAM provides the option for data accessors to be billed directly for expenses associated with their requests, rather than those costs being incurred by the data controller. DAM is designed to work as a component within a broader data hosting platform, and also as a standalone service.

### Identity Concentrator

This repository contains the Identity Concentrator ("IC"), which performs the role of a [GA4GH Passport Broker](http://bit.ly/ga4gh-passport-v1#passport-broker)

#### The problem

In order to access controlled-access datasets, data accessors must prove to data controllers that they have the qualifications required by the data controller. This is done by submitting an application to the data controller who manually reviews the information provided. If acceptable, the data controller adds the data accessor to a whitelist or other static access control mechanism. The data accessor must then use the specific identity (e.g. a Google Cloud credential) for which the access was granted. The data accessor must repeat this process for each dataset that they wish to work with. This results in data accessors accumulating many disparate identities, each specific to a different data controller.

#### The solution

The IC is an open-source service that securely combines identity qualifications (e.g. I am an academic researcher, I am a physician, I have taken ethics training XYZ, etc) collected from disparate sources into a single identity that can be used to access controlled-access datasets. Without the IC, data accessors must obtain and manage identities that are specific to a given data controller (e.g. a data controller hosting data on Google Cloud may have required data accessors to obtain Google Cloud credentials rather than using their existing corporate or academic credential).

Because data accessors often require access to data siloed across many locations, data accessors must shift between identities to obtain the data that they need. This makes running complex workflows that depend on data from diverse sources challenging and unreliable. With IC, data accessors (and the workbench platforms that they use) are able to combine relevant identities before executing a given workflow. This enables the workflow to leverage all data that the data accessor is permitted to access, regardless of how fragmented their identity qualifications may be. IC is designed to work as a component within a broader platform, but can also be deployed as a standalone service.

Some datasets will have visa requirements that can be collected from multiple sources, but need to be presented on one passport. The IC can combine lists of visas pertaining to one user from various visa sources.

For more information, visit:

*  [GA4GH Overview of Passports](http://bit.ly/ga4gh-passport-v1#overview) and
   [GA4GH Researcher Identity Introduction](http://bit.ly/ga4gh-ri-intro).
*  [GA4GH Passport v1.0](http://bit.ly/ga4gh-passport-v1) full specification.
*  [GA4GH AAI OpenID Connect Profile v1.0](http://bit.ly/ga4gh-aai-profile) specification.
*  [GA4GH](https://www.ga4gh.org/)

**IMPORTANT: This is an early pre-release that should only be used for testing and demo purposes. Only synthetic or public datasets should be used. Customer support is not currently provided.**

## Contributing to the repository

For information on how to contribute to the repository, see [How to Contribute](CONTRIBUTING.md).

## Notice

This is not an officially supported Google product.

## How to Deploy

For information on how to deploy Federated Access, see [How To Deploy Federated Access](deploy.md).
The `deploy.bash` script is designed to get a test environment up and running quickly and make it easy to develop services that use them in a non-sensitive environment.

When planning the next phase where these services need to be prepared for a production environment with live, sensitive data, the [productionization documentation](productionization.md) can be helpful.

More technical information about components and how to manage them:

*  [Technical Guide to DAM](dam.md)

## Troubleshooting

See the [how-to](howto.md) guide.

## Configuration

For configuration examples, see [deploy/config/dam-template](deploy/config/dam-template) and [deploy/config/ic-template](deploy/config/ic-template).

For more information, see [IcConfig](proto/ic/v1/ic_service.proto) and [DamConfig](proto/dam/v1/dam_service.proto).

## Test Personas

Test Personas are a means to create mock test users that are defined to hold a set of visas. The DAM can use test personas to verify that access privileges behave as expected for users with such visas. Each test persona reports an "access list" that describes the resources and roles their visas provide access to.

A playground environment includes a Test Persona Broker ("Persona Broker") that allows users to impersonate Test Personas. If the DAM and IC are both set up to trust a Persona Broker, then end to end tests and training can be conducted.

**Note:** Production deployments of DAM and IC should never be configured to trust Persona Brokers. However, production DAMs can still use Test Personas to verify access without allowing users to impersonate them.

## APIs

For information about API endpoints available in Federated Access components,
please refer to [API documentation](apis.md).

## Bugs, feature requests and general feedback

Please consult the open [issues](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/issues), or file a new issue. Your feedback is appreciated!
