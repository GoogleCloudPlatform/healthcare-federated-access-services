# User Journeys

## Overview

[Data Access Manager](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services#data-access-manager) (DAM) provides a mechanism for users -- such as
researchers -- to get access to cloud resources using identities and
permissions/qualifications carried on their access tokens from an [Identity
Concentrator](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services#identity-concentrator)
(IC) or other Passport Broker. Passport Brokers have users sign in and collect
Passport Visas that are passed down to the DAM for use in access policies for
data or service requests.

## Researcher Analysis on Cloud

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/fa_researcher_cloud_usage.svg">

In the above diagram, a researcher wishes to run a Virtual Machine (VM) in their
home organization or in a public cloud supported by DAM, or multiple VMs some
combination of places:

1.  Perform discovery of available datasets.
    *  Determine which datasets the DAM has available.
    *  The user or a tool of their choosing collects datasets that should be
       allowed given the researcher's status and controlled access grants from
       Data Access Committees (DACs).
    *  Initiate a request to DAM for access to the dataset collection desired.

1.  The user is redirected to get Passports and Visas from appropriate locations
    for the given collection of datasets being requested.
    *  The user chooses an Identity Provider to authenticate with (i.e. login).
    *  Once the login successfully completes, the Identity Concentrator (IC)
       or other compliant Passport Broker packages up Passport Visas for use
       by the DAM.

1.  The user is redirected back to the DAM to complete the request to access
    the collection of datasets.
    *  DAM decides if the request meets the policy requirements of all datasets
       being requested.
    *  DAM allocates a "DAM access token" that can be used to get cloud
       resources for the collection of datasets.
    *  The application calls the DAM API `checkout` endpoint to get cloud
       resource URLs, tokens, and interface information.

1.  The user starts a compute job on a set of VMs.
    *  The user directly or via the application takes steps to grab the cloud
       URLs and related tokens and provide them as inputs to the VM(s).
    *  VM(s) may run on premises (i.e. in the researcher's home institution or
       private cloud), or on any supported public cloud, or some combination
       thereof.
    *  VM(s) use different tokens or signed URLs to access resources across
       clouds as needed with the appropriate ACLs and billing settings.

