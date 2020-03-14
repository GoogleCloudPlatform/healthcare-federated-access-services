# Productionization Best Practices

## Production Concepts

The following projects are used for the cross-project and environment scenarios:

*   Data hosting project: the GCP project hosting datasets.

    For example, this project owns the data buckets or tabular data shared with
    the researcher.

*  Service account project: the GCP project hosting service accounts for
   researchers. DAM allocates service accounts that represent the user for
   accessing dataset.

*  Server (IC/DAM) hosting project: the GCP project hosting IC and DAM server.

## Productionization

To create a production environment, complete the following steps:

1.  Run the following setup script to generate your own private and public keys:

    ```
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -RSAPublicKey_out > public.pem
    cat private.pem
    cat public.pem
    ```

1.  Edit `deploy.bash` or `deploy-gke.bash` and ensure the following is configured correctly:

    *  The CloudSQL `username` and `password`.
    *  [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json) file. This file contains a list of DAM administrators.

1.  Edit the following configuration files to provide the security and options
    for your production environment:

    *  [IC's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/permissions_master_main_latest.json) file. This file contains a list of IC administrators.
    *  [DAM's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/secrets_master_main_latest.json)
    *  [IC's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/secrets_master_main_latest.json)
    *  [DAM's main config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/config_master_main_latest.json)
       file. Remove any references to the personas broker, especially in the
       section for trusted passport and visa issuers. Also edit the file to
       ensure that policies, clients, other security settings, options, and
       other attributes match your needs for a production environment.
    *  [IC's main config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/config_master_main_latest.json)
       file. Remove any references to the personas broker, especially in the
       section for identity providers. Also edit the file to ensure that
       clients, options, and other attributes match your needs for a production
       environment.
    *  OAuth client credentials
    *  IDP client credentials
    *  RSA keys

    **Warning:** Take care to not add or change anything that can expose Hydra's
    admin endpoints outside the VM (nginx is configured to guard this in the
    sample setup).

1.  Run the `deploy(_gke).bash` script and make sure you rebuild your images
    and do not install the "personas" playground component.

    *  The `prepare_project(_gke).bash` and `deploy(_gke).bash` are not designed for
       production use. You will need to develop your own version of these
       scripts that meets your deployment needs.
    *  Make sure that you run or re-run `project_init.bash` or a similar script
       whenever important service-dependency changes  have occurred. This
       must be run before redeploying federated access components like DAM and
       IC.
    *  Do not use `deploy.bash -b` as the `-b` flag skips rebuilding the
       components that are to be deployed. Using `-b` can make your deployment
       use out-of-date components.
    *  Remove the "personas" component and delete all references to it from
       both the DAM and IC configuration files. This component is for demoing
       a system, but it allows anyone to act as an administrator and is not
       appropriate for production use.
    *  Lock down or disable "icdemo" and "damdemo" to prevent exposing the
       `client_secret` to others who could use it to gain unwanted access to
       your systems.
    *  See `deploy.bash -h` for options on how to not build and deploy unneeded
       components. Once you have familiarized yourself with these options,
       edit your production deploy script so these unwanted components are
       removed permanently.

1.  The `hydra_reset` tool is not a good fit for production since it syncs to a
    configuration file and not the database. See
    [Reset and Production don't Mix](#reset-and-production-dont-mix) for
    details. The `endpoints.bash` files for DAM and IC make use of this feature
    to deal with unstable changes by forcing a file-level sync, but it must be
    removed for production. Other mechanisms should be developed based on
    how you manage manual upgrades to your database that impact the content,
    such as manual or scripted deletions of rows from the database.

1.  Review other [Security](#security) considerations during the planning phase
    of your deployment.

1.  DAM and IC support have multiple instances which can be made use of via
    `deploy.bash -e <environment>`, for example. If there are multiple instances
    of DAM making use of the same IAM project for accounts and permissions,
    problems related to cleanup can occur. Environments are not aware of
    each other and therefore the state used by one instance to make an account
    or token management decision does not reflect the state of another
    environment that is sharing the same service accounts. Production
    environments should have their own service account pool that is managed by
    only one deployment.

    *  If you have multiple deployments / environments, make sure they use
       different service account projects.
    *  It is recommended best practice to create a separate project just for the
       service account pool, and not enable or run any other services within
       that project. Set up permissions such that DAM running in a different
       project has permissions to the service account pool project.

1.  By default on GCP, DAM can only allocate service accounts to 100 unique
    users who need permissions to datasets. For production workloads, the number
    of users should be estimated well ahead of deployment. Submit a request to
    GCP customer service to increase this quota to your estimated number and
    specify the project ID that will need this quota override.

1.  It is recommended to deploy your datasets in different projects than DAM
    and IC as well. This makes the permissions easier to keep separate and
    explicit.

    *  The service account that DAM runs under will need permissions to manage
       access to the dataset.
    *  If the datasets use "requester pays" features of file or table
       storage, then set the appropriate permissions for DAM to accept billing
       for IAM policy and other API management. On GCP, DAM has an configuration
       option to attach all billable IAM policy actions to another project. When
       this option is not set, the project DAM is deployed in will be billed for
       such usage.

1.  DAM has the ability to share a resource's Policy Basis and provide
    Visa Rejection Details to help non-administrator users to collect
    visas that meet the requirements and troubleshooting rejected requests for
    resources.

    *  A **Policy Basis** gives a list of
       [visa types](https://bit.ly/ga4gh-passport-v1#ga4gh-standard-passport-visa-type-definitions)
       that the policy is looking for and may share a subset of the specific
       policy details. This is available as part of dataset discovery as well
       as when requests for access fail due to policy requirements not being
       met. The level of detail that a Policy Basis exposes may vary over time
       based on integration needs as federated systems develop.
    *  **Visa Rejection Details** provide insight into which visas were
       considered by the DAM as part of visa processing, but were ignored or
       "rejected" due to not meeting requirements. These details include which
       part of the policy was not met. For example, it may indicate that a
       specific visa is not issued by a trusted visa issuer, and hence it was
       rejected.

    Both Policy Basis as well as Visa Rejection Details are shared with
    non-administrator users by default. If sharing this information with users
    does not meet the sharing restrictions for the deployment, then set one or
    both of the following settings for DAM as needed:

       ```
       export HIDE_POLICY_BASIS=true
       export HIDE_REJECTION_DETAILS=true
       ```

    To verify both these settings are in affect, request a resource in a staged
    instance for a user that does not meet the visa policy requirements and
    view the response from DAM to the authorization request. Policy Basis can
    be verified alone by requests to
    `/dam/v1alpha/{realm}/resources/{name}/views/{view}/roles/{role}` as well
    as various other dataset discovery endpoint.

1.  Docker container entrypoint scripts includes a weak secret: SECRETS_SYSTEM

    For more information, see the following files:

    *  deploy/build/dam/entrypoint.bash for GAE Flex
    *  deploy/build/ic/entrypoint.bash for GAE Flex
    *  deploy/build-gke/dam/entrypoint.bash for GKE
    *  deploy/build-gke/ic/entrypoint.bash for GKE

    `SECRETS_SYSTEM` is the secret that hydra used to encrypt the sensitive
    information in SQL database. This variable should not be stored as plain text
    in a file. Consider using [secrets-management](https://cloud.google.com/solutions/secrets-management)
    in production.

1.  Make sure that the `FEDERATED_ACCESS_ENABLE_EXPERIMENTAL` option is turned
    off and not later turned on. It can be turned off by removing the `export`
    from the configuration.

1.  Manage which clients are able to allocate the `account_admin`, `link`, and
    `sync` scopes. These scopes are not needed by most clients.

    *  Having no more than one or two clients that can allow users to change
       their profile or link their accounts is recommended.
    *  Clients that are permitted to use these scopes should keep `link` scoped
       access tokens as short-lived and revoke or discard them immediately after
       they serve their purpose.
    *  It is recommended to not use `account_admin` nor `link` scopes with
       refresh tokens. Generally it is better if the user modifies their account
       within a short window of time, then re-authenticates if more edits are
       desired later.
    *  The `sync` scope should be provided to only "admin tool" type clients
       as a Hydra client sync can be performed using just a `client_id` and
       `client_secret`.

## Security

### DAM Background Processes

DAM runs background processes on an intermittent basis as a means to clean up
service accounts and revoke access on tokens that live longer than the visas and
policies allow.

*  Choose a deployment option that keeps at least one instance of DAM
   running at all times.
*  Monitor the GCP Key Garbage Collector (`gcp_key_gc`) using Stackdriver
   monitoring. Here is an example query (substitute `${YOUR_ENVIRONMENT}` and
   `${YOUR_PROJECT_ID}' before executing the query):
      ```
      resource.type="gae_app"
      resource.labels.module_id="dam-${YOUR_ENVIRONMENT?}"
      logName=("projects/${YOUR_PROJECT_ID}/logs/appengine.googleapis.com%2Fstdout" OR
              "projects/${YOUR_PROJECT_ID}/logs/appengine.googleapis.com%2Fstderr")
      ("gcp_key_gc" AND
      ("\"Completed\"" OR "\"Incomplete\"" OR "\"Aborted\"" OR "\"Conflict\"" OR "errors during execution"))
      ```
   Once you see logs, remove the `Completed` option to filter only error
   states. Tune the query according to your setup and requirements. When ready,
   set up a Stackdriver metric that can be used to create an alert.

   **Tip:** If you are not deploying a separate environment using `-e`, then
   the `module_id` may be just "dam".

   Note that strings may be updated in the code from time to time, so it is
   recommended that you also create an alert for the absence of the "Completed"
   state to detect when the alerts may be outdated and no longer work correctly.

### Reset and Production don't Mix

The DAM and IC both have features and capabilities to "reset" their databases to
the initial state as captured by the configuration files. These features are
intended for developers or other non-production use cases as a "reset" does not
properly clean up existing state.

*  **DO NOT USE THESE "RESET" TOOLS AND ENDPOINTS IN PRODUCTION ENVIRONMENTS.**
*  These are "hard reset" development tools that don't consider implications on
   underlying service dependencies.
*  IAM accounts and permissions within the configured cloud project(s) are not
   cleaned up. This may allow users to access data indefinitely unless you
   undertake manual intervention.
*  Hydra state is not necessarily synced correctly depending on how the
   reset is performed.
*  The `hydra_reset` tool syncs Hydra based on configuration files. This may
   not reflect the current state in the database.
*  There may be other side effects of `reset` tools that are not appropriate for
   production use, and these side effects may vary from time to time.

### Malicious Tokens

Checks are performed in `lib/auth` component to detect if the token is
potentially malicious. Currently, Federated Access components will reject such
tokens and then report their occurrence in the [audit logs](#audit-logs). No
further action is taken by the services themselves.

The admin may want to:

*  monitor the audit logs for these occurrences
*  contact the token owner or upstream admin to take action
*  revoke these tokens and related tokens
*  consider disabling the user's account

## Audit Logs

Access audit logs are available via
[Stackdriver](https://cloud.google.com/stackdriver) and are available for
administrators in the
[logs viewer](https://console.cloud.google.com/logs/viewer) component of
[GCP developer console](https://console.cloud.google.com/) by
selecting the appropriate GAE Application for the given Federated Access
environment. See
[Stackdriver Logging documentation](https://cloud.google.com/logging/docs)
for more details about Stackdriver logs in general. Go to the advanced filter
and use `logName="projects/YOUR_PRORJECT_ID/logs/federated-access-audit"`.

Access audit logs are provided in the following format:

```
{
 httpRequest: {
  referer: ...
  remoteIp: ...
  requestMethod: ...
  requestUrl: ...
  userAgent: ...
 }
 insertId: ...
 jsonPayload: {
 }
 labels: {
  error_type: ""
  pass_auth_check: "true"
  project_id: ...
  request_path: ...
  service_name: "dam"
  service_type: "dam"
  token_id: ...
  token_issuer: ...
  token_subject: ...
  tracing_id: ...
  type: "access_log"
 }
 logName: "projects/YOUR_PROJECT_ID/logs/federated-access-audit"
 receiveTimestamp: ...
 resource: {
  labels: {
   instance_id: ...
   project_id: ...
   zone: ...
  }
  type: "gce_instance"
 }
 timestamp: ...
}
```

If you want to turn off these additional audit logs, set the following
environment variable before the Federated Access services start:

```
export FEDERATED_ACCESS_DISABLE_AUDIT_LOG=true
```

After deploying with this environment variable, make some Federated Access API
requests and verify that the logs are not being written to Stackdriver.
