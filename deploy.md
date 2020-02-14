# How To Deploy Federated Access

## Before you start

To deploy federated access you must create a Google Cloud project. This project
will include the following:

*  dataset hosting
*  service account hosting
*  ic and dam hosting

The following projects are used for the cross project and environment scenarios:

*   Data hosting project: the GCP project hosting datasets.

    For example, this project owns the data buckets or tabular data shared with
    the researcher.

*  Service account project: the GCP project hosting service accounts for
   researchers. DAM allocates service accounts that represent the user for
   accessing dataset.

*  Server (IC/DAM) hosting project: the GCP project hosting IC and DAM server.

## Install Google Cloud SDK

If you haven't already done so on your machine, you will need to install
the Google Cloud SDK to use the `deploy.bash` scripts.

To install the Google Cloud SDK, in your GCP project, run the following command:

```bash
gcloud auth application-default login
gcloud auth login

export GCP_USERNAME=<project-admin-account, e.g. user@example.com>
gcloud config set account ${GCP_USERNAME?}
```

For more information, see the [SDK documentation](https://cloud.google.com/sdk/docs).

## Fetch the latest release from GitHub

If you haven't already done so, install `git` and related tools as per the
Github's [Set up Git](https://help.github.com/en/github/getting-started-with-github/set-up-git) documentation.

If this is your first time installing Federated Access components, you will need
to clone the repository:

```
git clone https://github.com/GoogleCloudPlatform/healthcare-federated-access-services.git
```

**Tip:** If you are less familiar with `git`, then [Git Basics](https://git-scm.com/book/en/v2/Git-Basics-Getting-a-Git-Repository) is a good starting point
to understanding the command line interface.

Then `checkout` the latest release:

```
cd healthcare-federated-access-services
git pull
export FA_VERSION=$(git describe --tags)
git checkout ${FA_VERSION?}
```

**Important:** It is recommended to checkout git's release tags (as per
`FA_VERSION` above) instead of `master` as releases have typically gone through
additional testing processes.

## Create a test Google Cloud deployment of Federated Access services

To create a Google Cloud project, do the following:

1.  Create a GCP project using the GCP Developer Console.

1.  Learn about Project Initialization [here](#project-initialization). When
    ready, run:

    ```
    ./project_init.bash -p <gcp-project-id>
    ```

1.  Run the following setup script to deploy components with default settings
    that can be tested:

        ```
        export PROJECT=<gcp-project-id>
        ./deploy.bash
        ```
    **Note:** you may wish to run `./deploy.bash -i` the first time to have
    the script pause between steps where you can look for recent errors and
    break the script (CTRL-C) if you do not wish to proceed.

    This script configures the following:

     *  IC and DAM are deployed on [GAE Flex](https://cloud.google.com/appengine/docs/flexible/)
        in [us-central](https://cloud.google.com/appengine/docs/locations).
     *  [CloudSQL](https://cloud.google.com/sql/docs/postgres/) is deployed for
        [Hydra](https://github.com/ory/hydra) in [us-central1](https://cloud.google.com/sql/docs/mysql/locations)
        with the following configuration:
        *  type: "postgres"
        *  name: "hydra"
        *  username: "hydra"
        *  password: "hydra"

For more information on deploying federated access services, see
[deploy.bash](deploy.bash) and run `deploy.bash -h` for help.

Configuration details are also contained within the following files:

*  [IC's config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/config_master_main_latest.json)
*  [IC's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/permissions_master_main_latest.json)
*  [IC's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/ic-template/secrets_master_main_latest.json)
*  [DAM's config.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/config_master_main_latest.json)
*  [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json)
*  [DAM's secrets.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/secrets_master_main_latest.json)

## Test with test client

After installing the test Google Cloud deployment as documented above, you can
use the test playground features to try the IC and DAM components.

In a browser, open `https://icdemo-dot-${YOUR_PROJECT_ID}.appspot.com/test` and `https://damdemo-dot-${YOUR_PROJECT_ID}.appspot.com/dam/test`.

**Note:** if you supplied an environment namespace via
`deploy.bash -e <environment>`, then you will need to visit these pages instead:
`https://icdemo-${ENVIRONMENT}-dot-${YOUR_PROJECT_ID}.appspot.com/test` and
`https://damdemo-${ENVIRONMENT}-dot-${YOUR_PROJECT_ID}.appspot.com/dam/test`.

For example, `deploy.bash -e staging -p my-project` would create an `icdemo`
page of: `https://icdemo-staging-dot-my-project.appspot.com/test`.

## Project Initialization

**Warning**: The project initialization may not be appropriate for production
environments, and should be reviewed carefully before attempting to use it for a
production environment.

Project initialization prepares a GCP project to host Federated Access services.
For example, it initializes or enables the following:

*  enabling gcloud services on the project
*  setting up Google App Engine (GAE) to deploy services within a given region
*  configuring IAM permissions on dependent GCP services
*  setting up databases for use by Hydra
*  setting up Hydra configuations
*  creating a demo GCS bucket for use by the template configurations
*  deploying a default GAE application placeholder such that other services
   can be deployed (i.e. a default must exist first before deploying DAM, IC,
   etc.)
*  ... and potentially more items as well

If any dependencies change with these underlying services, then project
initialization will need to be performed again. In this way, a rebuild of the
underlying services can attempt to deploy these changes. Examples include:

*  changes to usernames and passwords of databases
*  deploying to different regions or using other underlying services to deploy
*  Hydra binary or configuation changes
*  permission changes
*  etc.

**Tip:** if over time your deployment environment does not match your
expectations and it was deployed using `project_init.bash`, then you may wish
run `project_init.bash` again to see if a rebuild of your environment fixes the
problem.

## Environment variables for the deploy script

It may be useful to create a wrapper script to control some settings to
`deploy.bash`. Here is an example `my_deploy.bash`:

```
export PROJECT=<my-gcp-project>
export DAM_CONFIG=${CUSTOM_CONFIG_DIR?}/dam
export IC_CONFIG=${CUSTOM_CONFIG_DIR?}/ic

./deploy.bash "$@"
```

**Note:** You can still pass flags and parameters through this script to
`deploy.bash`, and `-p <project>` can still override the PROJECT environment
variable.

## Configure a production environment

1.  You will need to generate your own private and public keys. For example,
    this can be done by running the following setup script:

    ```
    openssl genrsa -out private.pem 2048
    openssl rsa -in private.pem -RSAPublicKey_out > public.pem
    cat private.pem
    cat public.pem
    ```

1.  Edit `deploy.bash` and ensure the following is configured correctly:

    *  The CloudSQL `username` and `password`.
    *  [DAM's permissions.json](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/deploy/config/dam-template/permissions_master_main_latest.json) file. This file contains a list of DAM administrators.

1.  Edit configuration files to provide the security and options you will need
    and are required for production:

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

1.  When running the `deploy.bash` script, make sure you rebuild your images
    and do not install the "personas" playground component.

    *  The `project_init.bash` and `deploy.bash` are not designed for production
       use. You will need to develop your own version of these scripts that
       meets your deployment needs.
    *  Make sure your run or re-run `project_init.bash` or a similar script
       whenever important service-dependency changes may have occurred. This
       must be run before redeploying federated access components like DAM and
       IC.
    *  Do not use `deploy.bash -b` as the `-b` flag skips rebuilding the
       components that are to be deployed. Using `-b` can make your deployment
       use out-of-date components.
    *  Remove the "personas" component and delete all references to it from
       both the DAM and IC configuration files. This component is for demoing
       a system, but it allows anyone to act as an administrator and is not
       appropriate for production use.
    *  Lock down or disable "icdemo" and "damdemo" to not expose the
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

1.  DAM and IC support having multiple instances which can be made use of via
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

### Security

#### DAM Background Processes

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
   Once you see logs, remove the `"Completed"` option to filter only error
   states. Tune the query according to your setup and requirements. When ready,
   set up a Stackdriver metric that can be used to create an alert.

   **Tip:** If you are not deploying a separate environment using `-e`, then
   the `module_id` may be just "dam".

   Note that strings may be updated in the code from time to time, so it is
   recommended that you also create an alert for the absence of the "Completed"
   state to detect when the alerts may be outdated and no longer work correctly.

#### Reset and Production don't Mix

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

#### Malicious Token

Checks are performed in `lib/auth` component to detect if the token is
potentially malicious. Currently, Federated Access components will reject such
tokens and then report their occurrence in the [audit logs](#audit-logs). No
further action is taken by the services themselves.

The admin may want to:

*  monitor the audit logs for these occurrences
*  contact the token owner or upstream admin to take action
*  revoke these tokens and related tokens
*  consider disabling the user's account

#### Audit Logs

Access audit logs are available via
[Stackdriver](https://cloud.google.com/stackdriver) and are available for
administrators in the
[logs viewer](https://console.cloud.google.com/logs/viewer) component of
[GCP developer console](https://console.cloud.google.com/) by
selecting the appropriate GAE Application for the given Federated Access
environment. See
[Stackdriver Logging documentation](https://cloud.google.com/logging/docs)
for more details about Stackdriver logs in general.

Access audit logs are provided in the following format:

```
TODO
```

If you want to turn off these additional audit logs, set the following
environment variable before the Federated Access services start:

```
export FEDERATED_ACCESS_DISABLE_AUDIT_LOG=true
```

After deploying with this environment variable, make some Federated Access API
requests and verify that the logs are not being written to Stackdriver.
