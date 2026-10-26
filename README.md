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
- Apple/SSWG dependencies only:
  - [swift-crypto](https://github.com/apple/swift-crypto) `3.0.0..<5.0.0`, for SHA-256 (PKCE) and
    HMAC-SHA256 (Facebook's `appsecret_proof`); on Apple platforms it uses CryptoKit;
  - [swift-nio](https://github.com/apple/swift-nio) from 2.86.0,
    [swift-nio-ssl](https://github.com/apple/swift-nio-ssl) from 2.31.0 and
    [swift-asn1](https://github.com/apple/swift-asn1) from 1.2.0, for the default HTTP transport
    (see [Transports](#transports)). The floors match Perfect-SMTP 6.0.0.

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
    // Keep the state and PKCE verifier server-side until the callback, one key per provider.
    session["oauth.pending.google"] = try JSONEncoder().encode(request.pending)
    return request.url  // redirect the browser here
}

// Route 2: GET /auth/google/callback?code=...&state=...
func finishSignIn(callbackURL: URL, session: inout [String: Data]) async throws -> OAuthUserProfile {
    // Remove it before completing, so it can only be used once.
    guard let data = session.removeValue(forKey: "oauth.pending.google") else {
        throw OAuth2Error.stateMismatch
    }
    let pending = try JSONDecoder().decode(PendingAuthorization.self, from: data)
    let profile = try await google.completeAuthorization(callbackURL: callbackURL, pending: pending)
    // profile.userid is never empty. Key accounts on (profile.loginType, profile.userid).
    return profile
}
```

`completeAuthorization` checks the state and the pending authorization, exchanges the code (sending
the PKCE verifier and the same `redirect_uri`), runs the provider's token checks, fetches the profile,
and throws if anything is missing. Use `completeAuthorization(code:state:pending:)` if your framework hands you the query
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
| `.missingAuthorizationCode`, `.invalidCallback` | the callback had neither `code` nor `error`, or a `code` over 4 KB |
| `.invalidPendingAuthorization` | the `PendingAuthorization` was created by another provider or client, is expired, is inconsistent with the configuration (redirect URL, PKCE, verifier), or was already used by this instance |
| `.providerError(response)` | an error body from a token or API endpoint; `response.code` is the provider's code (`invalid_grant`, `bad_verification_code`, `OAuthException`...), `response.standardCode` the RFC 6749 one if it is one |
| `.httpStatus(Int)` | any other non-2xx, including redirects (never followed) |
| `.invalidResponse`, `.missingUserID` | the response wasn't the JSON expected (including a non-Bearer `token_type` or a compressed body), or had no user id |
| `.invalidIDToken`, `.restrictedDomainMismatch` | Google id_token and domain checks |
| `.timedOut`, `.cancelled`, `.network`, `.responseTooLarge` | transport failures, or the calling task was cancelled |
| `.insecureURL`, `.invalidConfiguration` | a non-HTTPS endpoint, or a bad redirect URL / parameter |

`exchange` and `completeAuthorization` check the state first, then the pending authorization, and
only then report an `error=` callback, so a provider error arriving with an expired pending
authorization throws `.invalidPendingAuthorization` rather than `.authorizationDenied`.

Error descriptions never include secrets: provider text is truncated, stripped of control
characters, and has the client secret (always) and the code, verifier and tokens from the failed
request (from 8 characters) replaced with `<redacted>`, in raw and percent-encoded forms.

## Security model

- **State (CSRF).** `authorizationRequest()` generates 32 random bytes (`SystemRandomNumberGenerator`,
  base64url). If you pass your own `state:`, it must be 32 to 512 characters. The callback's state
  must be non-empty and equal to the stored one, compared in constant time, before any network
  request. `AuthorizationState.generate()` and `AuthorizationState.verify(returned:expected:)` are
  public if you run the flow yourself.
- **PKCE** (RFC 7636, S256), as the OAuth 2.0 Security BCP (RFC 9700) recommends for every client,
  confidential ones included. It is on by default where the provider documents support (see the
  table) and can be forced either way with `usePKCE:` in the configuration. Google sends and checks an
  OpenID Connect `nonce` instead when PKCE is turned off.
- **Pending authorizations.** `PendingAuthorization` holds the state, the PKCE verifier and the
  nonce, and its JSON contains them in clear: keep it in a server-side session store, not a
  client-readable cookie. Use one session key per provider and delete it when the callback arrives
  (as the quick start does). `exchange` also refuses one that was created by another provider or
  client ID, is older than `pendingAuthorizationMaxAge` (default 10 minutes), carries a redirect URL
  other than the configured one or a malformed verifier, or has already been completed by the same
  provider instance (remembered in memory for the max age).
  - These are consistency checks against honest mistakes (a pending from another provider, a stale
    one), **not tamper detection**: the value isn't signed, so a hand-built pending with the right
    fields passes, and so does one with its nonce removed. Its integrity rests on keeping it
    server-side, where the client can't change it.
  - The reuse check is best-effort: it is per process, and under a flood (100,000 live entries) it
    keeps only the newest half, so an older state could be accepted again within the max age. A
    replay would still need the victim's server-side pending authorization. Deleting it from the
    session on completion is what makes it single-use, across a cluster too.
- **Redirect URI.** One fixed, registered `redirectURL` per provider: absolute HTTPS (HTTP only to
  `localhost`, `127.0.0.1` and `::1`), no fragment. It is sent unchanged on the authorization request and the exchange. 1.x appended
  `?session=<session token>` to it, which leaked the session token to the provider and into logs;
  2.0 doesn't, and you shouldn't put session identifiers in it either. Use a cookie-backed session.
- **id_token trust.** An id_token is only used during a code exchange, when it came straight from
  the provider's token endpoint over TLS. OpenID Connect Core §3.1.3.7 lets a client skip the
  signature check in that case, so PerfectOAuth2 does, but it checks the issuer, audience (`aud`
  contains your client ID, and `azp` equals it when present or when there are several audiences),
  numeric expiry and issue time (5 minutes' leeway, at most 24 hours apart), a non-empty `sub`, and
  the nonce when one was sent. With `restrictedDomain`, the token's `hd` claim must match.
  `OAuth2Token.idToken` is exposed raw: never trust an id_token from anywhere else (a browser, a query
  string, storage) without verifying its signature against the provider's keys.
- **Profiles come from the provider's API, not from tokens.** `fetchProfile(token:)` accepts any
  access token, including one your app stored or received from elsewhere, and trusts only the
  provider's userinfo response for it. It never reads the token's id_token. Google's
  `restrictedDomain` is checked there too, against userinfo's `hd`, so a forged id_token can't get
  round it. But **`fetchProfile` doesn't prove the token was issued to your app**: the access token's
  audience isn't checked, so a token another app obtained for the same user (token substitution)
  would be accepted. Use it with tokens from your own `exchange`/`completeAuthorization`, or verify
  the audience yourself first (for Google, `https://oauth2.googleapis.com/tokeninfo` returns the
  token's `aud`).
- **Email.** `email` is only trustworthy when `emailVerified` is true. GitHub's profile email is never
  marked verified.
- **Tokens on the wire.** Access tokens are sent in the `Authorization: Bearer` header, never in a URL.
  Token requests are form-encoded POSTs with `client_secret` in the body. Every URL is built with
  `URLComponents`, and every value is percent-encoded (including `+`, `&` and `=`).
- **HTTP limits.** Each request has a whole-request deadline (`OAuth2HTTPOptions.timeout`, default
  30 s), a response cap (`maximumResponseBytes`, default 1 MiB, checked against `Content-Length` and
  while reading), no redirects, no cookies or cache, `Accept-Encoding: identity` with any other
  `Content-Encoding` (and any `Transfer-Encoding` other than plain `chunked`) refused when the
  response head arrives, and HTTPS only (HTTP to loopback for testing). With the default
  `NIOTransport` these are hard bounds on every platform: reading stops and the connection closes the
  moment one is hit. Only `token_type` Bearer is accepted. Salesforce's identity URL must be HTTPS on
  the login host or an allowed suffix (`identityHostSuffixes`) before the token is sent to it.
- **TLS.** The default transport verifies the certificate chain against the system trust store and
  the host name (with SNI), and for a host name also requires a matching DNS subjectAltName, so a
  certificate that only names an IP address is refused (NIOSSL alone accepts an IP SAN equal to the
  dialed address). Nothing is written to the connection until the handshake and that check pass, so
  a server whose certificate is refused never sees the request or the client secret in it.
- **No secrets in output.** `description`, `debugDescription`, `dump` and `Mirror` of
  `OAuth2ClientConfiguration`, `OAuth2Token`, `OAuthUserProfile`, `PendingAuthorization`,
  `AuthorizationRequest`, `AuthorizationCallback` and `OAuth2HTTPRequest` show `<redacted>` for
  secrets, tokens, codes, state, nonces and verifiers. (`Codable` encoding of `PendingAuthorization`
  is for storage and isn't redacted.)

## Transports

- **`NIOTransport` (default).** A small HTTP/1.1 client on SwiftNIO, one connection per request,
  on `MultiThreadedEventLoopGroup.singleton` (nothing to shut down; pass `group:` to use your own).
  Hard size, time and redirect bounds as above, on every platform. Use
  `NIOTransport(tlsConfiguration:)` to trust a private CA. **It ignores proxy settings**: URLSession
  honours the system and environment proxies, this client doesn't.
- **`URLSessionTransport` (opt-in).** Foundation's URLSession, with the same deadline, cap, identity
  encoding and no-redirect rules. Use it if you need a proxy. **It isn't reliably bounded**: on Linux
  corelibs Foundation keeps reading and discarding a cancelled response in the background (severe on
  Swift 6.2), and on macOS Darwin can decompress part of a gzip body before the refusal takes effect
  (233–368 MB in 3 of 9 runs against a 255 KB gzip bomb). `NIOTransport` is the bounded one.
- **Your own `OAuth2Transport`**, set with `OAuth2HTTPOptions(transport:)`: for example one on
  AsyncHTTPClient (below), or one that routes through your proxy.

```swift
let google = Google(configuration: OAuth2ClientConfiguration(
    clientID: "your-client-id", clientSecret: "your-client-secret",
    redirectURL: URL(string: "https://example.com/auth/google/callback")!,
    http: OAuth2HTTPOptions(transport: URLSessionTransport(timeout: 30))  // opt in to URLSession
))
```

50 back-to-back calls against a local server that sends an endless body, each capped at 16 KiB
(5 s deadline):

| Transport | Platform | Wall time | Read over loopback | Peak RSS | Notes |
|-----------|----------|-----------|--------------------|----------|-------|
| `NIOTransport` | macOS 27 | 0.18 s | 44 MB | 44 MB | descriptors unchanged |
| `NIOTransport` | Swift 6.2, linux/arm64 | 0.19 s | 136 MB | 141 MB | descriptors unchanged |
| `NIOTransport` | Swift 6.2, linux/amd64 (emulated) | 0.25 s | 71 MB | 87 MB | descriptors unchanged |
| `NIOTransport` | Swift 6.4, linux/arm64 | 0.20 s | 154 MB | 125 MB | descriptors unchanged |
| `NIOTransport` | Swift 6.4, linux/amd64 (emulated) | 0.24 s | 69 MB | 82 MB | descriptors unchanged |
| `URLSessionTransport` | Swift 6.2, linux/arm64 | 44.9 s | 37.9 GB | 487 MB | 6 calls ended only at the 5 s deadline; 35 more descriptors open afterwards |
| `URLSessionTransport` | Swift 6.2, linux/amd64 (emulated) | 127 s | 102 GB | 920 MB | 16 calls ended only at the deadline; 43 more descriptors open afterwards |
| `URLSessionTransport` | Swift 6.4, linux/arm64 | 0.19 s | 365 MB | 123 MB | |

("Read over loopback" is what the server managed to write before the connection closed, mostly
into kernel socket buffers on the NIO rows; peak RSS is the whole test process. The NIO rows used
TLS from a local test CA, the URLSession rows plain HTTP to a socket server.) The endpoints are the providers' own fixed TLS hosts, so this needs a compromised or
impersonated provider to trigger, but the default no longer depends on that. Corelibs
FoundationNetworking also leaks about 76 bytes per URLSession request (seen with LeakSanitizer).

A transport on [AsyncHTTPClient](https://github.com/swift-server/async-http-client), checked by
building and running it against local endless, slow, gzip and redirecting servers:

```swift
import AsyncHTTPClient
import Foundation
import NIOCore
import PerfectOAuth2

/// Whole-request deadline, streamed size cap, no redirects, no compression.
struct AsyncHTTPClientTransport: OAuth2Transport {
    let client: HTTPClient  // configured with redirectConfiguration: .disallow
    var timeout: TimeInterval = 30
    var maximumResponseBytes = 1 << 20

    func send(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse {
        // execute(timeout:) only bounds the response head, so race the whole exchange, body
        // included, against the deadline.
        try await withThrowingTaskGroup(of: OAuth2HTTPResponse.self) { group in
            group.addTask { try await perform(request) }
            group.addTask {
                try await Task.sleep(nanoseconds: UInt64(timeout * 1_000_000_000))
                throw OAuth2Error.timedOut
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw OAuth2Error.timedOut }
            return first
        }
    }

    private func perform(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse {
        var outgoing = HTTPClientRequest(url: request.url.absoluteString)
        outgoing.method = request.method == .post ? .POST : .GET
        for (name, value) in request.headers { outgoing.headers.replaceOrAdd(name: name, value: value) }
        outgoing.headers.replaceOrAdd(name: "Accept-Encoding", value: "identity")
        if let body = request.body { outgoing.body = .bytes(ByteBuffer(bytes: body)) }
        do {
            let response = try await client.execute(outgoing, timeout: .seconds(Int64(timeout.rounded(.up))))
            if let encoding = response.headers.first(name: "Content-Encoding"), encoding.lowercased() != "identity" {
                throw OAuth2Error.invalidResponse("compressed response refused")
            }
            let body = try await response.body.collect(upTo: maximumResponseBytes)
            return OAuth2HTTPResponse(status: Int(response.status.code), body: Data(buffer: body))
        } catch is NIOTooManyBytesError {
            throw OAuth2Error.responseTooLarge(limit: maximumResponseBytes)
        } catch let error as HTTPClientError where error == .deadlineExceeded {
            throw OAuth2Error.timedOut
        }
    }
}

// One client for the process, with redirects off (decompression is off by default).
let httpClient = HTTPClient(
    eventLoopGroupProvider: .singleton,
    configuration: HTTPClient.Configuration(redirectConfiguration: .disallow)
)
let google = Google(configuration: OAuth2ClientConfiguration(
    clientID: "your-client-id", clientSecret: "your-client-secret",
    redirectURL: URL(string: "https://example.com/auth/google/callback")!,
    http: OAuth2HTTPOptions(transport: AsyncHTTPClientTransport(client: httpClient))
))
```

## Providers

| Provider | Type | Default scopes | PKCE default | Profile endpoint | Notes |
|----------|------|----------------|--------------|------------------|-------|
| Google | `Google(configuration:restrictedDomain:)` | `openid profile` (`openid` always added) | on (nonce when off) | OIDC `openidconnect.googleapis.com/v1/userinfo` | id_token validated on every exchange; `restrictedDomain` sends `hd` and enforces both the token's `hd` claim and userinfo's `hd`; `authorizationRequest(offlineAccess:)` |
| GitHub | `GitHub(configuration:)` | `read:user` | on | `api.github.com/user` | GitHub added PKCE in 2025. Errors arrive as HTTP 200 with `error`. OAuth apps don't issue refresh tokens unless token expiration is enabled |
| Facebook | `Facebook(configuration:graphAPIVersion:)` | none | off | Graph `/me` | Graph `v23.0` by default; sends `appsecret_proof`. No refresh tokens |
| LinkedIn | `LinkedIn(configuration:)` | `openid profile` | off | OIDC `api.linkedin.com/v2/userinfo` | LinkedIn documents PKCE only for approved native clients. Add `email` for the address |
| Salesforce | `try Salesforce(configuration:loginHost:identityHostSuffixes:)` | `id` | on | identity URL from the token response | `loginHost` for sandboxes (`test.salesforce.com`) and My Domain. Identity hosts default to `.salesforce.com`/`.salesforce.mil`; other clouds (Government Cloud Plus, China) aren't verified, add their suffixes. Add `refresh_token` for refresh tokens |
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

Override `authorizationParameters` for extra login-link parameters (their names are then reserved),
`makeAuthorizationRequest(scopes:state:additionalParameters:)` to change how every login link is
built (it's dispatched dynamically, also through `any OAuth2Provider`), and
`validate(_:pending:)` for token checks that must pass before an exchange returns.

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
| `provider.exchange(code:state:sessionToken:)` / `exchange(code:state:redirectURL:)` / `exchange(authorizationCode: AuthorizationCode(code:redirectURL:))` | `try await provider.exchange(callback: AuthorizationCallback(url:), pending:)` |
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
- **Pending authorizations expire** after 10 minutes (`pendingAuthorizationMaxAge`) and only work
  with the provider, client ID and redirect URL that created them.
- **Only Bearer tokens** are accepted, and compressed responses are refused.
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

The tests are hermetic: provider flows run against an in-memory transport, both built-in transports
against local servers on 127.0.0.1 (a socket server over HTTP, and a SwiftNIO server with TLS from a
throwaway test CA for the certificate checks). Nothing contacts a real provider.

The pre-Swift-6 code (the Swift 3 `OAuth2` target and the `LocalAuthentication` username/password
system) is on the [`legacy`](https://github.com/PerfectlySoft/Perfect-Authentication/tree/legacy)
branch.

## License

Apache License 2.0. See [LICENSE.md](LICENSE.md).
