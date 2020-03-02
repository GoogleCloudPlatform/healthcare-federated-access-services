# Federated Access FAQs


## How do I Revoke a Token?

### Revoking IC/DAM tokens

To revoke an IC/DAM token use the "/oauth2/revoke" endpoint on IC/DAM as follows:

1.  Use `base64` to encode `CLIENT_ID:CLIENT_SECRET` as `CLIENT`.
1.  Call the revoke endpoint.

The following code sample shows how to revoke a token:

```
export CLIENT=`echo ${CLIENT_ID?}:${CLIENT_SECRET?} | base64 -w 0`

curl -X POST ${URL?}/oauth2/revoke \
     -H 'Content-Type: application/x-www-form-urlencoded' \
     -H 'Accept: application/json' \
     -H 'Authorization: basic ${CLIENT?}' \
     -d 'token=${TOKEN?}'
```

For more information see [Revoke OAuth2 tokens](https://www.ory.sh/docs/hydra/sdk/api#revoke-oauth2-tokens).

### Revoking GCP access tokens

Regular GCP access tokens are not keys, and will expire in 1 hour or less.

For revoking GCP service account keys (used for >1 hour tokens) you must have
administrator permissions on the GCP project. You can use the GCP developer
console to filter service account keys by account name and delete the keys.

If you don't have administrator permissions on the GCP project, you can contact
your IC/DAM administrator to revoke them for you.

## How do I recover a deleted Service Account?

If you accidently deleted a service account and want to undelete it, complete
the following steps:

1.  Read [Undeleting a Service Account](https://cloud.google.com/iam/docs/creating-managing-service-accounts#undeleting)
    to understand the process and limitations.

1.  Go to the [Stackdriver Log Viewer](https://console.cloud.google.com/logs/viewer?minLogLevel=0&expandAll=false&interval=P1D&resource=service_account&advancedFilter=resource.type%3D%22service_account%22%0A%22DeleteServiceAccount%22%0A) and create an advanced query. You can modify this example to filter out log entries
    until you find the `delete service account` operation for the account you
    would like to recover.

1.  Expand the `operation details` > `resource` > `labels`, and copy the
    `unique_id`.

1.  On the command line, execute the following `gcloud` command:

       ```
       <set your gcloud project if you haven't already done so>

       gcloud beta iam service-accounts undelete <unqiue_id>
       ```
