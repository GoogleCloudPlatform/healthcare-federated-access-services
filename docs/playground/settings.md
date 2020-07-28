# Playground Settings

## Overview

The quickstart [deployment guide](deploy.md) will get the Playground components
up and running. This section will discuss making changes to the Playground.

## Importing Config Changes

In addition to using the administration config UIs, it is possible to replace
the IC configuration or DAM configuration from file into the data storage layer.
Also note that if a system is using the Persona Broker to allow users to
impersonate mock users, updates can only be done via file-based configurations.

For example, to allow the administrator to have `viewer` access to the default
dataset provided by the default configuration, the steps to roll this out from
files like this:

1.  Edit the `deploy/config/dam-template/config_master_main_latest.json` file.
1.  Under the `personas` section, replace the `administrator` persona with the
    following:

       ```
       "administrator": {
         "ui": {
           "label": "Administrator"
         },
         "passport": {
           "standardClaims": {
             "iss": "https://ic-${YOUR_PROJECT_ID}.appspot.com/oidc",
             "email": "admin@nci.nih.gov",
             "picture": "/identity/static/images/nih_identity.jpeg"
           },
           "ga4ghAssertions": [
             {
               "type": "ControlledAccessGrants",
               "source": "https://dbgap.nlm.nih.gov/aa",
               "value": "https://dac.nih.gov/datasets/phs000710",
               "assertedDuration": "1d",
               "expiresDuration": "30d",
               "by": "dac"
             }
           ]
         },
         "access": [
           "test-dataset/gcs_read/viewer"
         ]
       }
       ```
1.  Redeploy the Persona Broker (use the same `environment` as you used to
    deploy, or remove the `-e <environment>` all together if you did not use the
    environment feature):

       ```
       ./deploy.bash -e <environment> personas
       ```

Other than the Persona Broker, any changes you make to files will need to be
re-imported to replace existing configs.

**CAUTION:** This will wipe out any other changes you have made to the
configuration. Exercise extreme caution when using the `import` command with
production systems and validate the configs are correct before pushing them to
deployments.

```
./import.bash -p <project> -e <environment> -t <import_type> ic
```

or

```
./import.bash -p <project> -e <environment> -t <import_type> dam
```
