# HOWTO


## How To Revoke A Token?

For revoking an IC/DAM tokens you can use "/oauth2/revoke" endpoint on IC/DAM.

First use `base64` to encode `CLIENT_ID:CLIENT_SECRET` as `CLIENT`. Then call
the revoke endpoint.

```
export CLIENT=`echo ${CLIENT_ID?}:${CLIENT_SECRET?} | base64`

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
