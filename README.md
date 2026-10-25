# PerfectOAuth2

<p align="center">
    <img src="https://img.shields.io/badge/Swift-6.2%2B-orange.svg?style=flat" alt="Swift 6.2+">
    <img src="https://img.shields.io/badge/Platforms-macOS%2012%2B%20%7C%20Linux-lightgray.svg?style=flat" alt="Platforms macOS 12+ and Linux">
    <a href="LICENSE.md"><img src="https://img.shields.io/badge/License-Apache%202.0-lightgrey.svg?style=flat" alt="License Apache 2.0"></a>
</p>

Server-side OAuth 2.0 sign-in for Swift 6: the authorization-code flow with PKCE and CSRF state,
token refresh, and profile fetching for Google, GitHub, Facebook, Slack, LinkedIn and Salesforce.
Framework-agnostic: you supply two routes and a server-side session.

**Naming:** the repo is `Perfect-Authentication`, the package is `PerfectAuthentication`, and the
library product you import is `PerfectOAuth2`.

## Install

```swift
.package(url: "https://github.com/PerfectlySoft/Perfect-Authentication.git", from: "2.0.0"),

// target dependency
.product(name: "PerfectOAuth2", package: "Perfect-Authentication"),
```

## Requirements

- Swift 6.2 or later (`swift-tools-version: 6.2`, Swift 6 language mode).
- macOS 12 or later, or Linux (CI: Ubuntu 24.04 with Swift 6.2 and 6.4; macOS with Xcode 26.0.1
  and 26.6). iOS isn't a target: this is a confidential-client library for servers, and apps should
  use `ASWebAuthenticationSession` without embedding a client secret.
- One dependency: Apple's [swift-crypto](https://github.com/apple/swift-crypto)
  (`3.0.0..<5.0.0`), for SHA-256 (PKCE) and HMAC-SHA256 (Facebook's `appsecret_proof`). On Apple
  platforms it uses CryptoKit. Networking is Foundation's `URLSession`.

## Quick start

```swift
import Foundation
import PerfectOAuth2

// Once, at startup. Providers are immutable and Sendable: share one instance.
let google = Google(
    configuration: OAuth2ClientConfiguration(
        clientID: "your-client-id.apps.googleusercontent.com",
        clientSecret: "your-client-secret",
        redirectURL: URL(string: "https://example.com/auth/google/callback")!
    )
)

// Route 1: GET /auth/google
func startSignIn(session: inout [String: Data]) throws -> URL {
    let request = try google.authorizationRequest()
    // Keep the state and PKCE verifier server-side until the callback.
    session["oauth.pending"] = try JSONEncoder().encode(request.pending)
    return request.url  // redirect the browser here
}

// Route 2: GET /auth/google/callback?code=...&state=...
func finishSignIn(callbackURL: URL, session: inout [String: Data]) async throws -> OAuthUserProfile {
    guard let data = session.removeValue(forKey: "oauth.pending") else {
        throw OAuth2Error.stateMismatch
    }
    let pending = try JSONDecoder().decode(PendingAuthorization.self, from: data)
    let profile = try await google.completeAuthorization(callbackURL: callbackURL, pending: pending)
    // profile.userid is never empty. Key accounts on (profile.loginType, profile.userid).
    return profile
}
```

`completeAuthorization` checks the state, exchanges the code (sending the PKCE verifier and the same
`redirect_uri`), runs the provider's token checks, fetches the profile, and throws if anything is
missing. Use `completeAuthorization(code:state:pending:)` if your framework hands you the query
parameters instead of the URL.

`OAuthUserProfile` has `userid`, `firstName`, `lastName`, `displayName`, `picture`, `email`,
`emailVerified`, `loginType`, `token` (an `OAuth2Token`: access, refresh and id tokens, expiry,
scopes) and `raw`, the provider's profile response as a `JSONValue`.

### Refreshing

```swift
let token = try await google.refresh(refreshToken: storedRefreshToken)
// token.refreshToken is the rotated refresh token if the provider sent one,
// otherwise the one you passed in, so it can always be stored back.
```

`scopes:` narrows the request to a subset of the granted scopes, and `includeClientSecret: false`
leaves the secret out for providers that reject it. Google only issues a refresh token when asked:
`google.authorizationRequest(offlineAccess: true)` adds `access_type=offline&prompt=consent`. Use it
when you need a refresh token and leave it off for routine sign-ins, so users aren't asked to consent
every time.

### Errors

Everything throws `OAuth2Error`:

| Case | Meaning |
|------|---------|
| `.stateMismatch`, `.invalidState` | CSRF check failed, or the stored state is unusable |
| `.authorizationDenied(response)` | the provider redirected back with `error=` (e.g. `access_denied`) |
| `.missingAuthorizationCode` | the callback had neither `code` nor `error` |
| `.providerError(response)` | an error body from a token or API endpoint; `response.code` is the provider's code (`invalid_grant`, `bad_verification_code`, `OAuthException`...), `response.standardCode` the RFC 6749 one if it is one |
| `.httpStatus(Int)` | any other non-2xx, including redirects (never followed) |
| `.invalidResponse`, `.missingUserID` | the response wasn't the JSON expected, or had no user id |
| `.invalidIDToken`, `.restrictedDomainMismatch` | Google id_token checks |
| `.timedOut`, `.network`, `.responseTooLarge` | transport failures |
| `.insecureURL`, `.invalidConfiguration` | a non-HTTPS endpoint, or a bad redirect URL / parameter |

Error descriptions never include secrets: provider text is truncated, stripped of control
characters, and has the client secret, code, verifier and tokens from the failed request replaced
with `<redacted>`.

## Security model

- **State (CSRF).** `authorizationRequest()` generates 32 random bytes (`SystemRandomNumberGenerator`,
  base64url). If you pass your own `state:`, it must be 32 to 512 characters. The callback's state
  must be non-empty and equal to the stored one, compared in constant time, before any network
  request. `AuthorizationState.generate()` and `AuthorizationState.verify(returned:expected:)` are
  public if you run the flow yourself.
- **PKCE** (RFC 7636, S256), as the OAuth 2.0 Security BCP (RFC 9700) recommends for every client,
  confidential ones included. It is on by default where the provider documents support (see the
  table) and can be forced either way with `usePKCE:` in the configuration. Keep
  `PendingAuthorization` server-side; it holds the verifier.
- **Redirect URI.** One fixed, registered `redirectURL`: absolute HTTPS (HTTP only to loopback hosts),
  no fragment. It is sent unchanged on the authorization request and the exchange. 1.x appended
  `?session=<session token>` to it, which leaked the session token to the provider and into logs;
  2.0 doesn't, and you shouldn't put session identifiers in it either. Use a cookie-backed session.
- **id_token trust.** An id_token is only used when it came straight from the provider's token
  endpoint over TLS. OpenID Connect Core §3.1.3.7 lets a client skip the signature check in that case,
  so PerfectOAuth2 does, but it checks the issuer, audience (`aud` contains your client ID, and `azp`
  equals it when present or when there are several audiences), expiry and issue time (5 minutes'
  leeway) and a non-empty `sub`. Google's `restrictedDomain` uses the `hd` claim of that validated
  token, and the userinfo `sub` must match the token's. `OAuth2Token.idToken` is exposed raw: never
  trust an id_token from anywhere else (a browser, a query string, storage) without verifying its
  signature against the provider's keys.
- **Email.** `email` is only trustworthy when `emailVerified` is true. GitHub's profile email is never
  marked verified.
- **Tokens on the wire.** Access tokens are sent in the `Authorization: Bearer` header, never in a URL.
  Token requests are form-encoded POSTs with `client_secret` in the body. Every URL is built with
  `URLComponents`, and every value is percent-encoded (including `+`, `&` and `=`).
- **HTTP limits.** Each request has a whole-request deadline (`OAuth2HTTPOptions.timeout`, default
  30 s), a response cap (`maximumResponseBytes`, default 1 MiB, checked against `Content-Length` and
  while streaming), no redirects, no cookies or cache, and HTTPS only (HTTP to loopback for testing).
  Salesforce's identity URL must be HTTPS on a Salesforce host before the token is sent to it.
- **No secrets in output.** `description`, `debugDescription`, `dump` and `Mirror` of
  `OAuth2ClientConfiguration`, `OAuth2Token`, `OAuthUserProfile`, `PendingAuthorization` and
  `OAuth2HTTPRequest` show `<redacted>` for secrets, tokens, state and verifiers.

### Response limits on Linux

On Darwin, cancelling at the size limit stops the download. On Linux, the call also returns as soon
as the limit is passed, but corelibs Foundation can go on reading and discarding the rest of the body
in the background for a while. In testing against an endless local body, every call returned within
0.03 s and peak memory stayed under 180 MB, though the background read consumed up to 2 GB of
loopback traffic. Provider responses are small and come from the providers' own HTTPS endpoints, so
this only matters if one of them is compromised. If you need a hard bound, plug in your own
transport (for example on AsyncHTTPClient) through `OAuth2HTTPOptions(transport:)`.

## Providers

| Provider | Type | Default scopes | PKCE default | Profile endpoint | Notes |
|----------|------|----------------|--------------|------------------|-------|
| Google | `Google(configuration:restrictedDomain:)` | `openid profile` (`openid` always added) | on | OIDC `openidconnect.googleapis.com/v1/userinfo` | id_token validated on every exchange; `restrictedDomain` sends `hd` and enforces the token's `hd` claim; `authorizationRequest(offlineAccess:)` |
| GitHub | `GitHub(configuration:)` | `read:user` | on | `api.github.com/user` | GitHub added PKCE in 2025. Errors arrive as HTTP 200 with `error`. OAuth apps don't issue refresh tokens unless token expiration is enabled |
| Facebook | `Facebook(configuration:graphAPIVersion:)` | none | off | Graph `/me` | Graph `v23.0` by default; sends `appsecret_proof`. No refresh tokens |
| LinkedIn | `LinkedIn(configuration:)` | `openid profile` | off | OIDC `api.linkedin.com/v2/userinfo` | LinkedIn documents PKCE only for approved native clients. Add `email` for the address |
| Salesforce | `try Salesforce(configuration:loginHost:)` | `id` | on | identity URL from the token response | `loginHost` for sandboxes (`test.salesforce.com`) and My Domain. Add `refresh_token` for refresh tokens |
| Slack | `Slack(configuration:)` | `openid profile` | off | OIDC `slack.com/api/openid.connect.userInfo` | Sign in with Slack (OIDC). User ids are per workspace: combine with `raw["https://slack.com/team_id"]` |

PKCE defaults are conservative: on where the provider documents S256 support for web apps with a
client secret, off where support is undocumented or limited. Providers ignore unknown parameters, so
turning it on is low-risk if your app is set up for it.

### Custom providers

`OAuth2` is the generic flow for any standards-following provider. Wrap it in a type that conforms
to `OAuth2Provider` to get `authorizationRequest`, `completeAuthorization` and `refresh`:

```swift
struct Gitea: OAuth2Provider {
    let oauth2: OAuth2
    let loginType = "gitea"

    init(configuration: OAuth2ClientConfiguration) {
        oauth2 = OAuth2(
            configuration: configuration,
            authorizationURL: URL(string: "https://gitea.example.com/login/oauth/authorize")!,
            tokenURL: URL(string: "https://gitea.example.com/login/oauth/access_token")!,
            defaultScopes: ["read:user"],
            usesPKCEByDefault: true
        )
    }

    func fetchProfile(token: OAuth2Token) async throws -> OAuthUserProfile {
        let user = try await oauth2.getJSON(
            URL(string: "https://gitea.example.com/api/v1/user")!, accessToken: token.accessToken)
        return try OAuthUserProfile(
            userid: user["id"]?.identifierValue, displayName: user["full_name"]?.stringValue,
            loginType: loginType, token: token, raw: user)
    }
}
```

Override `authorizationParameters` for extra login-link parameters, and `validate(_:)` for token
checks that must pass before an exchange returns.

## Migrating to 2.0

### From 1.x (and the pre-release `main`)

2.0 is a breaking release. Every call site changes:

| 1.x / pre-release `main` | 2.0 |
|---|---|
| `GoogleConfig.appid = ...` etc. (global `nonisolated(unsafe)` statics) | `Google(configuration: OAuth2ClientConfiguration(clientID:clientSecret:redirectURL:))`, built once and shared |
| `GoogleConfig.endpointAfterAuth` | `redirectURL` |
| `GoogleConfig.redirectAfterAuth` | removed; where to send the user after sign-in is your app's business |
| `GoogleConfig.restrictedDomain` | `Google(configuration:restrictedDomain:)` |
| `Google.loginURL(state: csrf, sessionToken:)` (static or instance) | `let request = try google.authorizationRequest()`; redirect to `request.url` and store `request.pending` |
| `Google.loginURL(..., offlineAccess: true)` | `google.authorizationRequest(offlineAccess: true)` |
| `Google.processAuthResponse(code:state:sessionCSRF:sessionToken:)` | `try await google.completeAuthorization(callbackURL:pending:)` or `completeAuthorization(code:state:pending:)` |
| `provider.exchange(code:state:sessionToken:)` / `exchange(code:state:redirectURL:)` | `try await provider.exchange(callback: AuthorizationCallback(url:), pending:)` |
| `provider.getUserData(accessToken) -> [String: Any]` | `try await provider.fetchProfile(token:) -> OAuthUserProfile` (fields typed, the rest in `raw: JSONValue`) |
| `OAuth2(clientID:clientSecret:authorizationURL:tokenURL:)` | `OAuth2(configuration:authorizationURL:tokenURL:defaultScopes:usesPKCEByDefault:)` with `URL`s |
| `getLoginLink(redirectURL:state:scopes:) -> String` | `authorizationRequest(scopes:state:additionalParameters:) -> AuthorizationRequest` |
| subclassing `OAuth2` (`open class`) | conform to `OAuth2Provider` and wrap an `OAuth2` (now `final`) |
| `OAuth2Token` class, `webToken: [String: Any]?` | `OAuth2Token` struct; `idToken: String?` (raw, see the trust model) and `expiresIn` |
| `OAuthUserProfile(userid:..., accessToken:, refreshToken:, loginType:)` | `try OAuthUserProfile(userid:..., loginType:, token:)`; `accessToken` and `refreshToken` are still readable |
| `OAuth2Error` struct with `code: OAuth2ErrorCode` | `OAuth2Error` enum; the provider's code is in `.providerError(response)` / `.authorizationDenied(response)` |
| `InvalidAPIResponse`, `APIConnectionError`, `InvalidInput`, `InvalidAuthorizationCodeError`, `AuthorizationCode` | `OAuth2Error` cases; `PendingAuthorization` |
| `Linkedin`, `SalesForce` | `LinkedIn`, `Salesforce` (the old names give a rename fix-it) |
| `refresh(refreshToken:scopes:includeClientSecret:)` | unchanged |

Behaviour changes to check:

- **No more `?session=` on the redirect URI.** Register the bare `redirectURL` with the provider,
  and keep `PendingAuthorization` in a cookie-backed server-side session.
- **State must be 32+ characters.** Let `authorizationRequest()` generate it.
- **Empty or missing user ids throw** `OAuth2Error.missingUserID` instead of signing the user in as `""`.
- **HTTP failures throw.** 1.x turned network errors, HTTP errors and non-JSON into an empty
  dictionary, so they surfaced as missing fields (or a profile with empty fields).
- **Default scopes:** GitHub `user` → `read:user` (1.x asked for write access); Google `profile` →
  `openid profile`.
- **Endpoints:** Google uses its OIDC userinfo endpoint (`sub` instead of v2's `id`; the values are
  the same). Slack moved from the legacy `identity.basic` flow to Sign in with Slack (OIDC): update
  your Slack app's redirect URL and scopes. Facebook moved from Graph v2.3/v2.8 to v23.0.
- **PKCE** is sent to Google, GitHub and Salesforce by default.

## Development

```sh
swift build --build-tests -Xswiftc -warnings-as-errors
swift test
```

The tests are hermetic: provider flows run against an in-memory transport, and `URLSessionTransport`
against a local socket server on 127.0.0.1. Nothing contacts a real provider.

The pre-Swift-6 code (the Swift 3 `OAuth2` target and the `LocalAuthentication` username/password
system) is on the [`legacy`](https://github.com/PerfectlySoft/Perfect-Authentication/tree/legacy)
branch.

## License

Apache License 2.0. See [LICENSE.md](LICENSE.md).
