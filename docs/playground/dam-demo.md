# Data Access Manager Demo

## DAM Demo

If installing the full "playground" functionality (i.e. this is done by default
if using deploy.bash), the DAM Demo page can be a useful tool to get comfortable
with how these flows work in practice.

1.  Visit `damdemo-dot-<project-id>.appspot.com/test` or, if you used an
    `environment` name as part of your deployment, visit
    `damdemo-<environment-name>-dot-<project-id>.appspot.com/test` instead.
1.  Click the `Include Resource` button for the default dropdowns. This will
    prepare one resource, view, role, and interface to send to the DAM `auth`
    endpoint.
1.  Click `Auth for Resources` to start the DAM `auth` flow.
1.  Follow the various steps presented through the DAM, IC, and IdP layers.
    *  In this case, choose the "Persona Playground" as the IdP when prompted,
       and do not use the "Google" IdP.
    *  When on the "Persona Playground" login page, choose "NCI Researcher"
       since this persona has the required Visa to meet the access policy for
       the selected resource.
    *  When prompted to release scopes, including Visas, click `Agree`.
1.  Once you have returned to the `damdemo` test page without errors, the
    `Cart Tokens` button should turn blue. Click it to have the test page call
    the DAM's `checkout` endpoint.
1.  After 1 to 3 seconds, you should see a table filled in with one row per
    requested resource URI.
    *  Below the table, you will see the `checkout` response JSON that was used
       to fill in the table.
    *  The table contains a clickable "path" that lets to test out the access
       token provided for the GCS bucket.
1.  Click the `https://www.googleapis.com/storage/v1/b/...` clickable text in
    the "path" column. The output below should change to show the metadata for
    the file(s) contained within the bucket.

**Note:** that the DAM refresh token provided is valid for only a very short
period by default.

