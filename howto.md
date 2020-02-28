# HOWTO


## How to Revoke a Token?

For revoking an IC/DAM tokens you can use "/oauth2/revoke" endpoint on IC/DAM.

First use `base64` to encode `CLIENT_ID:CLIENT_SECRET` as `CLIENT`. Then call
the revoke endpoint.

```
export CLIENT=`echo ${CLIENT_ID?}:${CLIENT_SECRET?} | base64 -w 0`

curl -X POST ${URL?}/oauth2/revoke \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -H 'Accept: application/json' \
     -H 'Authorization: basic ${CLIENT?}' \
     -d 'token=${TOKEN?}'
```

For more information see:
https://www.ory.sh/docs/hydra/sdk/api#revoke-oauth2-tokens

Regular GCP access tokens are not keys, and will expire in 1 hour or less.

For revoking GCP service account keys (used for >1 hour tokens) you need to have
administrator permissions on the GCP project. You can use the GCP developer
console to filter service account keys by account name, and delete the keys.

If you don't have administrator permissions on the GCP project, you can contact
your IC/DAM administrator to revoke them for you.

## How to Undelete a Service Account?

If you accidently delete a service account and wish to undelete it, you may
try the following:

1.  Read the guide to
    [Undeleting a Service Account](https://cloud.google.com/iam/docs/creating-managing-service-accounts#undeleting)
    to understand the process and limitations.

1.  Visit the [Stackdriver Log Viewer and cook up an advanced query](https://console.cloud.google.com/logs/viewer?minLogLevel=0&expandAll=false&interval=P1D&resource=service_account&advancedFilter=resource.type%3D%22service_account%22%0A%22DeleteServiceAccount%22%0A). Modify this example
    to filter out log entries until you find the `delete service account`
    operation for the account you would like to undelete.

1.  Expand the `operation details` > `resource` > `labels`, then copy the
    `unique_id`.

1.  On the command line, execute a `gcloud` command:

       ```
       <set your gcloud project if you haven't already done so>

       gcloud beta iam service-accounts undelete <unqiue_id>
       ```
