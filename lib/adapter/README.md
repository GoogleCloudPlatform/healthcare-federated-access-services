This folder contains adaptors for various platforms hosting data (e.g. GCP).

An adaptor translates the generic GA4GH concepts to their corresponding ones for
the particular data host platform and applying them.  In particular:

* managing platform specific identities, e.g. creating a service account on GCP
* managing access permissions to resources hosted on the platform, e.g.
  permissions to access a GCS bucket on GCP
* managing platform tokens, e.g. obtaining a token for a service account on GCP

The code is organized by platform, e.g. adopters for GCP platform are located
under gcp subfolder.
