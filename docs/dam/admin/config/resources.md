# Resource Configuration

## Overview

Resources are datasets, data elements, or services that are to be shared.
[Data Access Manager](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services#data-access-manager) (DAM)
provides access controls within the hosting environment to allow users to
access these resources once particular requirements have been met as configured
by the Data Custodian or Data Host.

This section of the documentation will describe how to configure resources that
exist within a supported cloud environment to provide access to qualified users.

## Resource Data Model

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/dam_data_model.svg" width="800px">

Deconstructing a resource configuration:

1. **Views**: Each resource has at least one `view`, which allows a set of
   resource `items` to be offered when particular policies are met by the person
   requesting access to the view.

   *  A `view` may provide a slice of data within a resource. All resources
      **must** have a view, even if that view is named "all" and provides all
      the files or tables for that resource.
   *  Each view may provide only one resource service type, such as GCS buckets
      or BigQuery tables but not both. If related data consists of multiple
      service type items, then multiple views must be used to include them
      within the same `resource` within DAM.
   *  As per the example diagram above, one `view` of a `resource` may contain
      two GCS bucket `items` and another `view` of that same resource may
      contain two BigQuery table `items`.
      *  It could be that `item A1` and `item B1` contain the same data except
         in different formats, but this does not have to be the case.
      *  There could be 3 BigQuery tables in `view B` instead of the two listed,
         and they could contain EHR data that is not the same as the genomic
         data stored in `view A`.
   *  It is up to the administrator to organize the data in a logical way to
      manage it and provide items and views that make sense to the user
      as well as provide the right granularity of access control via DAM's
      access policy mechanisms. Access policies are applied at the `role` level
      *per view*.

1. **Items**: an `item` in some cases represents a set of data as stored by the
   underlying cloud systems, while in other cases may represent a web service.

   *  Each view has a list of `items` associated with it. The fields that are
      provided for an `item` vary based on the service type. For example, GCS
      bucket items provide `project` and `bucket` whereas BigQuery items provide
      `project` and `table`.
   *  Some `item` fields are required and others are optional. Each service type
      that DAM supports also publishes a `service descriptor` indicating what
      fields its `items` understand, and which of those fields are optional.
   *  For services such as Beacon, an item will contain fields that configure
      the audience, scope, and related fields to encode in a JWT token to send
      to a Beacon server. In this way, DAM authorizes access when policy
      conditions have been met when evaluating passports and allowed user
      groups.

1. **Roles**: each `view` publishes a set of available `roles`.

   *  Each `role` indicates a different access level on the data.
   *  Each `role` provides a different [set of policies](#role-based-access-policies)
      that the user must meet in order to gain access to that role.
      *  Users typically meet policy criteria by presenting a set of Passport
         Visas that prove that the criteria have been met.
      *  DAM also provides an email address allowlist mechanism to allow a small
         set of users to share data in the prepublication phase of a dataset
         before visas have been established.
      *  Allowlists and visas cannot be used within the same set of policies on
         a view of the data.
   *  For example, a view can publish three roles: `beacon`, `viewer`, and
      `editor`.
      *  `beacon` could represent a GA4GH Beacon discovery service that provides
         a way for users to discover if particular genomic variants are present
         within a dataset with low-risk of exposing PHI, yet still limit the use
         of this service to qualified Registered Access bona fide researchers.
      *  `viewer` could represent read access to the bytes of all items within
         the view.
      *  `editor` could represent read/write access to the items within the
         view.
   *  In advanced configurations, `service templates` can be edited to expose
      various roles for any given service type. Service templates do the work
      of taking a role like `viewer` and mapping it to roles on the underlying
      cloud platform that stores the data.

1. **Interfaces**: users select an `interface` that are published within each
   `view` to interact with the data. This is not shown in the diagram above
   because DAM exposes these automatically based on the service type that a
   `view` uses.

   *  Each `interface` represents a protocol or other mechanism to access the
      data.
   *  For example, the `gcs` service definition exposes two interfaces:
      1.  `gcp:gs` for using the GCS `gsutil` command line tool.
      1.  `http:gcp:gs` for using the GCS RESTful API.
   *  Users building workflows will need make use of tools that understand these
      interfaces in order to access the data. Different tools will make use of
      different interfaces. Some tools may support many interfaces.

## Role-based Access Policies

A set of [Access Policies](policies.md) are defined and then applied to roles
within resource views.

1. Each role that is activated **must** have one or more access policies
   associated with it.
1. Access Policies may be reused across different roles as well as different
   resources.
   *  When Access Policies include variables, these variable values must be
      assigned when binding the access policy to a specific roles within a
      `view`.
   *  Visit documentation on [Managing Multiple Similar
      Policies](policies.md#managing-multiple-similar-policies)
      for more information on access policy variables.
1. A `default role` is defined such systems know which role is recommended to
   highlight for a user's selection. Usually this is a `viewer` role, but it
   does depend on the use case and what level of access a typical user will
   need to complete their work.
1. If more than one access policy is specified for a given role, then **all**
   access policy requirements across this set of policies must be met for access
   to be granted.
   *  For example: consider having one policy that checks for `Bona Fide`
      researcher status, and another policy that checks for `Ethics Terms` have
      been agreed to.
      *  Defining a `discovery` role listing both `Bona Fide` and `Ethics Terms`
         will mean that the same passport must met both of these requirements.
      *  By defining these requirements separately, these policies can be
         combined with other policies as needed.
   *  For commonly reused cases, it may be better to create a single policy that
      checks for multiple visa requirements in one policy.
1. When configuring policies, ensure that they meet the organization's
   requirements and fully reflect the consents given for by the participants
   that provided the data. Consider the following GA4GH tiers of access:
   <img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/tiers_of_access.png" width="800px">
1. Most policies use GA4GH Passport Visas as evidence of meeting policy
   requirements.
1. DAM also supports an `allowlist` policy to directly add email addresses and
   group names in leu of Passport Visas.
   *  This is particularly handy in pre-publication use cases because several
      researchers need to collaborate as part of building and curating a
      dataset.
   *  Custom datasets may use DAM directly as part of the Data Access Committee
      approval by adding members to a group specific for a given dataset.
