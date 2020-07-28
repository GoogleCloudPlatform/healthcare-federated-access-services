# Cross-Component Auth Flows

## Auth Details for Requesting Access to Resources

Much like described in the [Researcher Cloud User
Journey](docs/shared/overview/journeys.md#researcher-cloud-user-journey), each
client application to DAM may redirect the user to DAM's `auth` endpoint to get
access to a set of resources. The user and/or the application would typically
select a set of resources, views, roles, and interfaces. This set of resources
may provide a set of access tokens and metadata for how to use them that include
multiple services and multiple public clouds within a single, multi-layered auth
flow.

There are three layers to the auth flow journey for the user. Each layer uses
the OpenID Connect (OIDC) protocol to obtain the identity and permissions
associated with the user:

1.  DAM's `auth` endpoint takes in a set of resource paths where each path
    contains the resource name, view name, role name, and interface name that
    the user is requesting. The user will be redirected to the 2nd layer of auth
    to obtain a Passport that covers the scope of the Visa requirements for all
    policies involved in that resource set. The default DAM configuration uses
    the Identity Concentrator (IC) to obtain this Passport via the
    `DEFAULT_BROKER` environment variable.

1.  IC's `auth` endpoint acquires a Passport to represent the user. It allows
    account linking so the user can login once and get access to a set of Visas
    across multiple accounts. The IC is an Identity Broker, meaning that it does
    not provide authentication natively but instead it is configured to provide
    a set of upstream Identity Providers (IdPs) to perform this step.
    *  The IC can request the `ga4gh_passport_v1` scope from upstream IdPs to
       acquire their Visas, then merge Visas from multiple linked accounts.
    *  The IC generates its own Passport, including its own identity for the
       user. This identity represents the user across all of the upstream IdPs
       that the user may choose to use as a source of Visas. In some cases,
       there are no Visa-providing upstream IdPs, but the IC can still represent
       the identity for these users.
    *  The IC adds some `LinkedIdentities` Visas to its Passport for users. This
       will include email address and the `subject` as the user is identified by
       upstream IdPs.
    *  The IC's Passport does not contain the visas, but allows access to them
       via the `ga4gh_passport_v1` scope via the `userinfo` endpoint. This
       allows the content of the Passport to be many kilobytes in size, but
       still allows the IC's `access token` to be small enough to be included as
       a bearer token on requests throughout the Passport service network.

1.  The upstream Identity Provider authenticates the user and provides any Visas
    it may have on the user.

Each layer of auth provides an opportunity for the user to agree to the release
of information to the previous layer in the chain. The user may choose not to
share some information if they feel it is unnecessary. Depending on what
information is shared, DAM policies guarding access to resources may not be
provided the information they need to permit access.

The OIDC flows listed above typically use the `code flow` mechanism to exchange
information. The code flow allows the minimal information needed to be exposed
to the user and their browser or other tool of reference as part of these flows.
For example:

*   The `icdemo` application ends up getting a `code` for an IC Passport, then
    the application uses it to show the user their passport, but does not get
    exposed to the IdPs access token directly.
*   The `damdemo` application ends up getting a `code` for a DAM access token,
    and does not get exposed to the IC Passport nor the upstream IdP access
    token directly.

**Tip:** See the [Three Layer Auth Flow](#three-layer-auth-flow)
for a full sequence diagram of a user going through a three layer auth flow with
these services.

## Three Layer Auth Flow

Full APP/DAM/IC/IdP cloud resource request flow:

![auth flow](assets/diagrams/3_layer_auth_flow.svg "Three Layer Auth Flow")

