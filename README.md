# PerfectOAuth2

<p align="center">
    <img src="https://img.shields.io/badge/Swift-6.2-orange.svg?style=flat" alt="Swift 6.2">
    <img src="https://img.shields.io/badge/Platforms-macOS%2012%2B-lightgray.svg?style=flat" alt="Platforms macOS 12+">
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0"></a>
</p>

Swift 6 OAuth2 client library with providers for Google, GitHub, Facebook, Slack, LinkedIn, and
Salesforce. No external dependencies — Foundation and URLSession only. Both library and test
targets build under strict concurrency.

**Note the naming:** this repo is `Perfect-Authentication`, but the package is
`PerfectAuthentication` and the library product you import is `PerfectOAuth2`.

**Ecosystem status:** standalone infrastructure — nothing else here currently depends on it. It's
finished and tested, awaiting a consumer (e.g. a future `PerfectNIOOAuth2` wrapper in Perfect-NIO),
not dead or abandoned code.

The pre-Swift-6 version of this package, including the original Swift 3 `OAuth2` target and the
un-resurrected `LocalAuthentication` username/password system, is preserved on the
[`legacy`](https://github.com/PerfectlySoft/Perfect-Authentication/tree/legacy) branch.

## Package

```swift
.package(url: "https://github.com/PerfectlySoft/Perfect-Authentication.git", branch: "main"),

// target dependency
.product(name: "PerfectOAuth2", package: "Perfect-Authentication"),
```

```swift
import PerfectOAuth2
```

## Configuration

Set config before your server starts. All properties are `nonisolated(unsafe) static var` to satisfy Swift 6 global state rules.

```swift
GoogleConfig.appid    = "your-client-id"
GoogleConfig.secret   = "your-client-secret"
GoogleConfig.endpointAfterAuth = "https://yourapp.com/auth/response/google"
GoogleConfig.redirectAfterAuth = "https://yourapp.com/"

// Google only: restrict to a G Suite / Workspace domain
GoogleConfig.restrictedDomain = "yourcompany.com"

GitHubConfig.appid    = "your-client-id"
GitHubConfig.secret   = "your-client-secret"
GitHubConfig.endpointAfterAuth = "https://yourapp.com/auth/response/github"
GitHubConfig.redirectAfterAuth = "https://yourapp.com/"

FacebookConfig.appid   = "your-app-id"
FacebookConfig.secret  = "your-app-secret"
FacebookConfig.endpointAfterAuth = "https://yourapp.com/auth/response/facebook"
FacebookConfig.redirectAfterAuth = "https://yourapp.com/"

SlackConfig.appid   = "your-client-id"
SlackConfig.secret  = "your-client-secret"
SlackConfig.endpointAfterAuth = "https://yourapp.com/auth/response/slack"
SlackConfig.redirectAfterAuth = "https://yourapp.com/"

LinkedinConfig.appid   = "your-client-id"
LinkedinConfig.secret  = "your-client-secret"
LinkedinConfig.endpointAfterAuth = "https://yourapp.com/auth/response/linkedin"
LinkedinConfig.redirectAfterAuth = "https://yourapp.com/"

SalesForceConfig.appid   = "your-client-id"
SalesForceConfig.secret  = "your-client-secret"
SalesForceConfig.endpointAfterAuth = "https://yourapp.com/auth/response/salesforce"
SalesForceConfig.redirectAfterAuth = "https://yourapp.com/"
```

## Usage

The library is framework-agnostic. You provide two routes — one to redirect the user to the provider, one to handle the callback. Both are plain async functions; session management is your responsibility.

### Step 1: Redirect to provider

```swift
// PerfectNIO example — route: GET /to/google
let csrf = session.data["csrf"] as? String ?? ""
let loginURL = Google.loginURL(state: csrf, sessionToken: session.token)
// redirect the user to loginURL
```

Or use the instance API for custom scopes:

```swift
let g = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
let url = g.loginURL(state: csrf, sessionToken: session.token, scopes: ["profile", "email"])
```

To get a Google refresh token, pass `offlineAccess: true` (see [Refreshing an access token](#refreshing-an-access-token)).

### Step 2: Handle the callback

```swift
// Route: GET /auth/response/google?code=...&state=...
let code  = request.queryParam("code") ?? ""
let state = request.queryParam("state") ?? ""
let csrf  = session.data["csrf"] as? String ?? ""

let profile = try await Google.processAuthResponse(
    code: code,
    state: state,
    sessionCSRF: csrf,
    sessionToken: session.token
)

// Store in session
session.userid           = profile.userid
session.data["loginType"]  = profile.loginType
session.data["accessToken"]  = profile.accessToken
session.data["firstName"]    = profile.firstName ?? ""
session.data["lastName"]     = profile.lastName ?? ""
session.data["picture"]      = profile.picture ?? ""

// redirect to redirectAfterAuth
```

### OAuthUserProfile

`processAuthResponse` returns an `OAuthUserProfile`:

```swift
public struct OAuthUserProfile: Sendable {
    public let userid: String
    public let firstName: String?
    public let lastName: String?
    public let picture: String?
    public let accessToken: String
    public let refreshToken: String?
    public let loginType: String   // "google" | "github" | "facebook" | "slack" | "linkedin" | "salesforce"
}
```

### Manual token exchange (advanced)

If you need access to the raw token (e.g. to call provider APIs beyond the profile):

```swift
let provider = GitHub(clientID: GitHubConfig.appid, clientSecret: GitHubConfig.secret)
let token = try await provider.exchange(code: code, state: state, sessionToken: session.token)
let userdata = await provider.getUserData(token.accessToken)
```

### Refreshing an access token

If the provider issued a refresh token, exchange it for a new access token with `refresh`
(the RFC 6749 `refresh_token` grant):

```swift
let provider = Google(clientID: GoogleConfig.appid, clientSecret: GoogleConfig.secret)
let token = try await provider.refresh(refreshToken: storedRefreshToken)
// token.refreshToken is the rotated refresh token if the provider sent one,
// otherwise the one you passed in, so it can always be stored back.
```

`scopes` optionally narrows the request to a subset of the originally granted scopes.
`includeClientSecret` defaults to `true`, which Google, Salesforce and LinkedIn require; pass
`false` for public clients that authenticate with `client_id` only. A rejected refresh token usually throws
`OAuth2Error` with code `.invalidGrant`; providers that answer with non-standard error codes (GitHub's
`bad_refresh_token`, Slack's `{"ok":false}`) surface as `InvalidAPIResponse` instead.

Not every provider issues refresh tokens: GitHub OAuth apps and Facebook don't, and Salesforce only
does when the `refresh_token` scope is granted. Google issues one the first time a user grants
offline access, and afterwards only when consent is prompted again. `offlineAccess: true` adds both
`access_type=offline` and `prompt=consent`:

```swift
let url = Google.loginURL(state: csrf, sessionToken: session.token, offlineAccess: true)
```

Use it when you need a refresh token (first sign-in, or when the stored one is lost or revoked), and
leave it off for routine sign-ins so users aren't asked to consent every time. While a Google Cloud
app's publishing status is "Testing", Google expires its refresh tokens after 7 days.

## Providers

| Provider   | Default scopes                     | Notes |
|------------|------------------------------------|-------|
| Google     | `profile`                          | Add `restrictedDomain` to enforce G Suite domain |
| GitHub     | `user`                             | Uses `Authorization: Bearer` header (not deprecated query param) |
| Facebook   | _(none)_                           | Profile fetch on Graph API v2.8; token exchange endpoint is still pinned to the older v2.3 (see Future work) |
| Slack      | `identity.basic identity.avatar`   | |
| LinkedIn   | `openid profile`                   | v2 userinfo endpoint (OpenID Connect) |
| Salesforce | `id`                               | Token exchange returns `idURL`; `getUserData` fetches from that URL |

## Error handling

```swift
do {
    let profile = try await Google.processAuthResponse(...)
} catch let e as OAuth2Error {
    // e.code: OAuth2ErrorCode (.invalidGrant, .accessDenied, .unsupportedResponseType, ...)
    // e.description: human-readable message
} catch is InvalidAPIResponse {
    // provider returned unexpected JSON
}
```

`processAuthResponse` throws `OAuth2Error(code: .unsupportedResponseType)` if `state != sessionCSRF`.

## Future work

- **LocalAuthentication target** — the original package included a username/password auth system (account schema, email verification, SMTP). It was not resurrected because it depends on `Perfect-SMTP` and `Perfect-Mustache`. The source is on the [`legacy`](https://github.com/PerfectlySoft/Perfect-Authentication/tree/legacy) branch if that work is ever picked up.

- **LinkedIn email scope** — add `email` to the default scopes and extract `email` from the `/v2/userinfo` response if email is needed.

- **Salesforce sandbox** — `SalesForce` hardcodes `login.salesforce.com`. Add `SalesForceConfig.domain` to support sandbox (`test.salesforce.com`) or My Domain instances.

- **Facebook Graph API version** — the profile-fetch endpoint (`getUserData`) uses `v2.8`, but the token-exchange endpoint (`Facebook.swift`) is still pinned to the older `v2.3`. Facebook's minimum supported version changes over time; bump both to a current version (v21+) when updating.

- **NIO session middleware integration** — the OAuth callback pattern (extract code/state, call processAuthResponse, write to session, redirect) is repetitive. A `PerfectNIOOAuth2` target in Perfect-NIO could provide pre-wired route handlers that accept a session driver and config. This is also the natural point at which this package would move from staged to actively consumed.

## License

Apache License 2.0 — see [LICENSE.md](LICENSE.md).
