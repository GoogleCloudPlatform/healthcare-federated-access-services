# Project Preparation

This page describes how to prepare a GCP project to host Federated
Access services.

## Overview

Project preparation needs to be performed before the first
deployment and time there are changes to the underlying
service configurations or code that Federated Access components depend on.

For example, the `prepare_project.bash` script initializes or updates the
following:

*  Enabling gcloud services on the project
*  Setting up Google App Engine (GAE) to deploy services within a given region
*  Configuring IAM permissions on dependent GCP services
*  Setting up databases for use by Hydra
*  Setting up Hydra configurations
*  Creating a demo GCS bucket for use by the template configurations
*  Deploying a default GAE application placeholder to which other services
   can be deployed (i.e. a default must exist first before deploying DAM, IC,
   etc.)

## How to prepare a GCP project for deployment

If you are executing project preparation for the first time, there are some
steps to perform first. For more information, see [How To Deploy a Federated Access Playground](deploy.md).

To re-execute after [changing service dependencies](#changes-to-service-dependencies),
do the following:

```
./prepare_project.bash -p <gcp-project-id>
```

## Changes to Service Dependencies

If any dependencies change with the underlying services, project
preparation must be performed again. In this way, a rebuild of the
underlying services can attempt to deploy these changes. Examples include:

*  Changes to usernames and passwords of databases
*  Deploying to different regions or using other underlying services to deploy
*  Hydra binary or configuration changes
*  Permission changes

**Tip:** If over time your deployment environment does not match your
expectations and it was deployed using `prepare_project.bash`, then you can
run `prepare_project.bash` again to see if a rebuild of your environment fixes the
problem.


