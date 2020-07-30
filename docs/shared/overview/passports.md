# GA4GH Passports

## Overview

This document will introduce the key benefits and challenges of using cloud
storage and computing, as well as discuss how the Identity Concentrator (IC)
and Data Access Manager (DAM) included in this GitHub repository use GA4GH
Passports to overcome these challenges.

## Use of Cloud

Data Controllers may set up multiple copies of datasets on one or more Clouds
and provide a Data Access Committee (DAC) to review and approve Data Access
Requests.

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/bring_compute_to_data.svg">

Instead of downloading data for local compute analysis, researchers may bring
their compute jobs to the cloud to work on the data directly.
*  **Data Remains in Place**: once the Data Controller publishes copies of the
   data for researchers to use, the data no longer needs to be downloaded
   outside of those cloud environments in order to do analysis.
   *  Copies may be published using different cloud environments and in
      different locations (within any regulatory compliance constraints of where
      the data is allowed to be).
   *  Copies give researchers more options as to where they can compute on the
      data, potentially even across datasets, while minimizing network egress
      and other charges.
*  **Compute Jobs Move to Cloud**: instead of data moving to a local researcher
   compute node, a researcher leveraging cloud compute moves the compute job's
   configurations to run near the data center hosting one or more of the copies
   in the cloud.

## Benefits of Cloud

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/benefits_of_cloud.svg">

1. **Security Improvements**: By bringing compute jobs to execute on the data
   in place, there is visibility to the Data Controller on how the data is being
   used.
   *  Avoids unmanaged downloads where access controls are unknown.
   *  Having unmanaged downloads increases the attack surface for viruses and
      hackers to compromise security measures. The cloud approach can limit
      this risk and insure a consistent, managed approach under the Data
      Controller's coordination.
   *  Access to data has a consistent means to provide Data Controllers with
      a full set of audit logs to investigate anomalies and put extra data
      governance monitoring in place.

1. **Regulation**: Downloading to where a researcher's compute resources are
   available does not always meet regulatory compliance requirements.
   *  Some PHI data has geolocation storage and processing requirements that
      do not allow the data to leave a particular geographic region.
   *  Other regulations may require a level of oversight over the data that
      unmanaged downloads does not comply with.

1. **Use Data in Place**: There are additional benefits to using data in place
   that are not already captured by the benefits above.
   *  Some data downloads will invoke network egress charges to move large
      amounts of data to the local compute node. These costs can be significant
      and reduce the budget available for biomedical analysis.
   *  Downloading and setting up a local copy of the data may be time consuming.
      In some cases, this can consume up to 30% of the research time that could
      have otherwise been available for analysis.

1. **Cloud Scale**: Reuse of shared compute hardware on demand puts the entire
   project's compute budget being used for analysis instead of long-term
   hardware ownership.
   *  Allows more compute to be available within a project's budget, thus
      providing for deeper and extended analysis.
   *  Allows analysis to complete faster by leveraging large pools of hardware
      that execute in parallel, yielding quicker turn-around. This gives more
      time and focus on iterations for better tuning and discovery insights.

1. **Advanced Tools**: Cloud has the ability to completely revolutionize
   research by providing best-of-breed research tools at cloud scale that are
   not available on systems within individual research labs.
   *  **Big Data** tools allow Clouds to process millions of individual records
      per second to bring scale and detail of analysis to a whole new level.
      These tools alone have the potential to make Principal Investigators up to
      three times more productive with their research when compared to using
      traditional analytical methods.
   *  **Machine Learning** and **Artificial Intelligence** are the next wave of
      tools that will help discover correlations between data that were not
      possible to see using traditional approaches.
   *  Cloud infrastructure providers are not only investing in providing
      hardware and storage, but are constantly innovating on these advanced
      tools to make them leading-edge. This allows researchers to focus on their
      research while infrastructure providers build the tools for researchers to
      use, which accelerates the entire process.

## Coordination Challenges

To use data in place, it can often require multiple systems to work together
in ways that create challenges. This increases as analysis includes more
datasets as part of one project where those datasets and compute environments
are heterogeneous.

For example, there may be multiple identities to manage, including:
*  Researcher's home organization identity.
*  Identity of the researcher as known by each Data Access Committee (DAC)
   using their sign-in systems.
*  Identities the researcher uses within each of the cloud environments
   involved in supplying data or compute nodes.

Then authorization controls need to be applied to those identities, and mapped
into each target data or computing environment. On top of this is the need to
provide good data governance to manage the correctness/appropriateness and
monitor usage.

In summary, these **coordination challenges** can be classified via these four
areas that all need to be overcome together:

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/challenges_of_cloud.svg" width="700px">

## Solution

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/passports_flow.svg">

1. **Passport Visa Assertion Sources**: these are organizations or systems
   working on their behalf that act as the Source of Authority to assert,
   authorize, or attest to something.
   *  An Assertion Source acts as the "source of truth" for what attestions or
      assertions.
   *  Systems downstream from these sources carry this information as inputs
      to policies that ensure users meet requirements for access.
   *  Assertions may include:
      *  Qualifications: such as role or industry certifications.
      *  Permissions: such as a grant of access to a particular set of data.
      *  Qualifying conditions: such as contractual agreements to terms of use.

1. **Upstream Passport Visa Issuers**: Passport Visas enter in a few places
   along the entire network, however these `Upstream` Visa Issuers are the
   systems that have access to the repositories where assertions are stored
   and are able to format those assertions in a verifiable GA4GH Passport Visa
   format for use by "downstream" systems (systems further to the right in the
   diagram).

1. **Upstream Passport Brokers**: Any Passport Broker ("Passport Issuer") that
   is in the network chain before coming to an Identity Concentrator (IC). The
   Identity Concentrator is the Passport Issuer system available in this GitHub
   repository.
   *  The IC can talk to other Passport Issuers to collect Passport Visas from
      their sources and pool Visas together for a given user within a single
      user's digital identity.
   *  Additional `LinkedIdentities` Visas may be added directly as a result of
      Upstream Passport Brokers aggregating identities for the user.

1. **Identity Concentrator** (Passport Broker): A Passport Issuer system that is
   available as part of this GitHub repository.
   *  It has support for combining Visa lists from Upstream Passport Brokers.
   *  It also has native understanding on how user identities map to cloud
      identities.
   *  It can authenticate a user via configuring any compliant OIDC sign-in
      service.
   *  It offers additional account management and auditing capabilities for
      users and administrators.

1. **Data Access Manager** (Passport Clearinghouse): A data and service access
   enforcement point where user requests for access to data are verified to meet
   policy requirements using Visas.
   *  Known as "DAM".
   *  Acts as an authorization server for underlying Cloud and On-Prem Services.
   *  The DAM has an extensible plug-in model to add support for more service
      platforms and expose configuration and identity/access options in a way
      that integrates with existing DAM APIs.
   *  See [DAM administration documentation](docs/dam/admin/README.md) to
      better understand the feature set and how it works.

1. **Cloud and On-Prem Services**: a set of services that a DAM can control
   identity and access management features in order to permit or revoke access
   to users that make access requests using the DAM.
   *  Supports Google Cloud Platform (GCP) services such as Google Cloud Storage
      (GCS) and BigQuery.
   *  Supports Amazon Web Services (AWS) such as S3 and RedShift.
   *  Supports integration with GA4GH services via related GitHub repositories.
      These services include:
      *  GA4GH Beacon: discover datasets using specialized queries for genomic
         variants.
      *  GA4GH Search: deeper searches into datasets for selecting cohorts.
      *  GA4GH WES: Workflow Execution Service that run analysis pipelines.
      *  GA4GH DRS: Data Repository Service that can locate copies of data in
         cloud.

## Benefits of Passports

Using the solution outlined above, passports overcome [coordination
challenges](#coordination-challenges) in the following ways:

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/benefits_of_passports.svg" width="700px">

The Identity Concentrator and Data Access Manager provide the ability to
evaluate policies across cloud computing environments and offer the data
governance controls to reflect and consistently maintain the intentions of the
Sources of Authority.
