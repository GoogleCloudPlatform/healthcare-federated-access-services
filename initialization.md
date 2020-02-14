# Project Preparation

This documentation explains how to prepare a GCP project to host Federated
Access services. Project preparation needs to be performed before the first
[deployment](deploy.md), as well as any time there are changes to the underlying
service configurations or code that Federated Access components depend on.

## Overview

For example, the `project_init.bash` script initializes or enables the
following:

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

## How to prepare a GCP project for deployment

If you are executing initialization for the first time, there are some steps
to perform first. See the [deployment](deploy.md) documentation.

To re-execute after [changing service dependencies](#changes-to-service-dependencies),
do the following:

```
./project_init.bash -p <gcp-project-id>
```

## Changes to Service Dependencies

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


