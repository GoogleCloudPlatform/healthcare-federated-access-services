# Identity Concentrator Demo

## IC Demo

If installing the full "playground" functionality (i.e. this is done by default
if using deploy.bash), the IC Demo page can be a useful tool to get comfortable
with how the [system flows](README.md#playground-configuration) work in
practice.

1.  Visit `icdemo-dot-<project-id>.appspot.com/test` or, if you used an
    `environment` name as part of your deployment, visit
    `icdemo-<environment-name>-dot-<project-id>.appspot.com/test` instead.

1.  Click the `Login` button. This will redirect you to the IC to proceed with
    the login flow.

1.  From the IC's login page, choose the "Persona Playground".
    *  Do not use the "Google" IdP as it will not have Visas and may not be
       fully configured by default.

1.  When on the "Persona Playground" login page, choose "NCI Researcher"
    since this persona has interesting Visas attached to their account.
    *  When prompted to release scopes, including Visas, click `Agree`.

1.  Once you have returned to the IC Demo test page without errors, click
    the `Token Exchange` button.
    *  This will take a the authentication code recieved via the sign-in process
       and return a Passport access token.

1.  The `Access Token` and `Refresh Token` boxes should now be filled in. Click
    the `Token Userinfo` Button to see information about the token and the visas
    it contains.
    *  The information should appear in a grey box at the bottom of the page.

**Note:** that the IC access token provided is valid for only a very short
period by default. Use the `Refresh Token` button to acquire a new access token
as needed.

