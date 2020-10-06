# Service Definition Configuration

## Overview

Service definitions describe the kinds of cloud or custom underlying data
sources and derived services for which you can manage access.

## Service Controllers

<img src="https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/raw/master/assets/diagrams/service_definitions.svg" width="1000px">

The Data Access Manager (DAM) has the ability to grant access to underlying
cloud and on-prem resources via the use of one or more Service Controllers.
Each Service Controller knows how to manage resources on a specific platform in
order to reflect the access decisions made by the DAM within those target
cloud or on-prem platforms or environments.

1. **User requests a resource**: A user makes a request for one or more
   resources and includes their GA4GH Passport as part of the request.

1. **Resource policy evaluation**: for each resource within the user's request,
   the DAM's Resource Policy Evaluation framework will determine if
   access is appropriate based on configuration settings for that resource.
   *  If any one resource fails the policy check, then no new access is granted
      for this request.

1. **Service Controller**: for each accepted request, service controllers will
   receive a set of requested resources that they can process.
   *  For example, if 3 resources are requested with 2 of them are on GCP and
      one on AWS, then the `GCP Service Controller` will receive 2 updates to
      make for GCS and/or BigQuery while the `AWS Service Controller` will
      receive the other 1 update.
   *  Service Controllers have a flexible response structure via key/value pairs
      to accommodate different forms of access credentials and tokens across
      various cloud and on-prem services.

1. **Cloud and on-prem service updates**: the service controller(s) update
   any permissions needed on the underlying cloud or on-prem services using the
   native cloud IAM and other service APIs.
   *  GCP generally uses service accounts and access tokens or service account
      keys to provide access.
   *  AWS uses a mix of service accounts and other account techniques such as
      Redshift credentials.
   *  In the case of GA4GH APIs, the DAM itself allocates JWT access tokens as
      an authorization server that may be used directly by Beacon or Search
      nodes based on JWT scopes.

## Service Interfaces

Each Service Controller exposes a set of **Interfaces**. An interface allows
a user to specify *how* they wish to use the resource, or *what* API will be
used to interact with the underlying cloud or on-prem services.

GCP Interfaces:
*  `gcp:gs`: file access to Google Cloud Storage (GCS) buckets.
   *  `File Creator`: Writes files (without read access).
      *  `roles/storage.objectCreator`
   *  `File Editor`: Read and write files plus manipulate file metadata.
      *  `roles/storage.objectViewer`
      *  `roles/storage.objectCreator`
   *  `File Viewer`: List and read files.
      *  `roles/storage.objectViewer`
*  `http:gcp:gs`: Similar to `gcp:gs`, but for use with HTTP RESTful APIs via
   `https://www.googleapis.com/storage/v1/b/${bucket}`.
*  `http:gcp:bq`: access to Google BigQuery tables and views.
   *  `BigQuery Editor`: query and modify tables and table metadata.
      *  `roles/bigquery.dataEditor`
   *  `BigQuery Viewer`: query tables and view table metadata.
      *  `roles/bigquery.dataViewer`

AWS Interfaces:
*  `aws:s3`: file access to S3 bucket directories and paths using tools.
   *  Exposes `s3://${bucket}` as the URI.
   *  A list of directories and files that may end in a `*` to indicate it is a
      prefix match.
   *  The `File Viewer` role by default provides the following permissions:
      *  `s3:GetObject`
      *  `s3:GetBucketLocation`
      *  `s3:ListBucket`
*  `http:aws:s3`: Similar to `aws:s3`, but for use with HTTP RESTful APIs via
   `https://s3.amazonaws.com/${bucket}`.
*  `web:aws:s3`: access of the file resources via the AWS web console.
*  `http:aws:redshift:arn`: Returns access to a Redshift cluster via the
   Redshift API.
   *  `DB User` role by default would map to include all of the following
      Redshift roles:
      *  `redshift:GetClusterCredentials`
      *  `redshift:CreateClusterUser`
      *  `redshift:JoinGroup`
*  `web:aws:redshift`: Similar to `http:aws:redshift:arn` but for access via
   the AWS Redshift web console.

Other Interfaces:
*  `http:beacon`: access token with scope for a given [GA4GH
   Beacon](https://beacon-network.org/) node.
   *  `Discovery Beacon Search without Metadata`: query genome data and return
      `found` or `not found` status.
      *  Scope: `registered`
      *  Role: `exists`
   *  `Discovery Beach Search with Metadata`: query genome data and receive
      metadata results.
      *  Scope: `registered controlled`
      *  Role: `metadata`

## Service Definitions

Each Service Controller takes in a set of inputs that provide the information
they need to reflect DAM policy access decisions on the target cloud or on-prem
platform.

1. Service Definitions that are exposed to Resource Views are sometimes
   referred to as Service Templates.
   *  The Resource View "fills in" the variables and settings that are exposed
      by the Service Definition, hence it invokes a Service Template.

1. Certain variables to be defined on resources.
   *  These are supplied by the Resource View that makes up the resource path
      for the requested data or service.
   *  Each Resource View requires that Service Definition variables are
      supplied. The list of variables required vs. optional will depend on the
      Service Definition that the Resource View is using.
   *  For example:
      *  GCP's GCS requires a GCS bucket name as well as a GCP project ID.
      *  AWS S3 requires an AWS bucket name.

1. A mapping of DAM roles to external service roles.
   *  DAM roles are used when configuring access on resources.
   *  External service roles are used to configure access on the cloud or other
      external services.
   *  For example, a DAM role `viewer` may include `roles/storage.objectViewer`
      when GCS is the underlying external cloud service, but otherwise may
      include `roles/bigquery.dataViewer` when BigQuery is the external cloud
      service.

The requested Service Interface is also part of the resource path such that
the Service Controller knows how to update the cloud or on-prem platform to
allow access for the requested method of access.

## Service Accounts

The GCP Service Controller as well as the AWS Service Controller use Service
Accounts to permit direct access to underlying cloud resources.

1. **Allocation of an account**: A service account is created to represent the
   end-user if one has not already been allocated on their behalf.
   *  Note: some interfaces on AWS, such as Redshift, may use other techniques
      as well.

1. **Update of permissions**: It is the allocated service account that is
   granted permissions to cloud resources using the cloud IAM API. Permissions
   and/or tokens are set to expire after a period of use, in part as indicated
   by the request TTL (but must not exceed a maximum as per the resource and
   general configuration).

1. **Token-based access**: Access tokens returned as part of the DAM's resource
   request are cloud-based tokens or other time-limited credentials specific to
   AWS Redshift.
   *  In order for tokens support the *requester-pays* billing model, the
      service account ID for each token is also provided and must be configured
      by the user to allow billing on these accounts.
   *  Each user has a stable and unique service account such that enabling
      billing on the service account is possible while knowing that
      user-supplied credentials are used as part of allocating service account
      tokens.

Cloud services may limit how many service accounts are available via various
quotas that are in place. Before deploying, you should ensure that your
`Service Account Pool` is sufficiently large for your user base. See
[productionization](../../../shared/admin/productionization.md#productionization-best-practices)
for more details.
