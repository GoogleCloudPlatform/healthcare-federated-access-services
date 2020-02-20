# How To Deploy a Federated Access Playground

This document is the quick-start guide to deploying Federated Access components
in a test environment and getting comfortable with how the system works. This
is referred to as a "playground" environment for trying out the use of
passports and access policies with [test personas](https://github.com/GoogleCloudPlatform/healthcare-federated-access-services/blob/master/README.md#test-personas).

**Note:** this environment is only for testing with synthetic and public
datasets. [Productionization](productionization.md) considerations are
documented separately for a later stage in the deployment process.

## Before you start

To deploy federated access you must create a Google Cloud project. This project
will include the following:

*  A sample dataset hosted as a file in a GCS bucket
*  An instantiation of the IC and DAM services

*  A playground passport broker that issues test passports to predefined personas
*  An IC login test page ("icdemo") and DAM resource request test page
   ("damdemo")

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

1.  To prepare the new project with all the service dependencies that Federated
    Access components need, execute the following:

    ```
    ./prepare_project.bash -p <gcp-project-id>
    ```

    **Note:** Learn about Project Preparation [here](prepare_project.md).

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
`deploy.bash`, and `-p <project>` can still override the `PROJECT` environment
variable.
