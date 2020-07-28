# Data Access Manager Resource Requests

## DAM checkout

After the auth flows have completed successfully, the user will have an access
token to DAM. This bearer token may be used by the `checkout` endpoint in DAM to
get access to the set of cloud access tokens and metadata for the resources
requested by that auth flow.

For example, the output of `checkout` may look something like this:

```
{
  "resources": {
    "https://dam-github-dot-project-example.appspot.com/dam/master/resources/test-dataset/views/gcs_read/roles/viewer/interfaces/gcp:gs": {
      "interfaces": {
        "gcp:gs": {
          "items": [
            {
              "uri": "gs://project-example-test-dataset",
              "labels": {
                "fidelity": "normalized",
                "geoLocation": "gcp:na/us/us-central1/us-central1-a",
                "partition": "all",
                "platform": "gcp",
                "topic": "variants",
                "version": "1.0"
              }
            }
          ]
        },
        "http:gcp:gs": {
          "items": [
            {
              "uri": "https://www.googleapis.com/storage/v1/b/project-example-test-dataset",
              "labels": {
                "fidelity": "normalized",
                "geoLocation": "gcp:na/us/us-central1/us-central1-a",
                "partition": "all",
                "platform": "gcp",
                "topic": "variants",
                "version": "1.0"
              }
            }
          ]
        }
      },
      "access": "0",
      "permissions": [
        "list",
        "metadata",
        "read"
      ]
    }
  },
  "access": {
    "0": {
      "credentials": {
        "access_token": "ya29.xxxxxxxxxxxxxxxxxxxxxxxxxx...",
        "account": "ixxxxxxxxxxxxxxxxxxxxxxx@project-example.iam.gserviceaccount.com"
      }
    }
  },
  "epochSeconds": 1584014173
}
```

