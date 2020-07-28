# Service Definition Configuration

## Overview

Service definitions describe the kinds of cloud or custom underlying data
sources and derived services for which you can manage access.

Service definitions will require:

1. Certain variables to be defined on resources.
   *  For example, URLs to a particular instance of a service.
1. A mapping of DAM roles to external service roles
   *  DAM roles are used when configuring access on resources.
   *  External service roles are used to configure access on the cloud or other
      external services.
   *  For example, a DAM role `viewer` may include `roles/storage.objectViewer`
      when GCS is the underlying external cloud service, but otherwise may
      include `roles/bigquery.dataViewer` when BigQuery is the external cloud
      service.
