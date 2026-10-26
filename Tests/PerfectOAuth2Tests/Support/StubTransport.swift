import Foundation
@testable import PerfectOAuth2

/// An in-memory transport: canned responses keyed by "host/path", every request recorded.
/// Unknown URLs throw, so nothing can reach a network.
final class StubTransport: OAuth2Transport, @unchecked Sendable {
    // Guarded by `lock`.
    private let lock = NSLock()
    private var routes: [String: OAuth2HTTPResponse] = [:]
    private var recorded: [OAuth2HTTPRequest] = []

    init() {}

    @discardableResult
    func on(_ url: String, status: Int = 200, _ body: String) -> StubTransport {
        let key = Self.key(URL(string: url)!)
        lock.withLock { routes[key] = OAuth2HTTPResponse(status: status, body: Data(body.utf8)) }
        return self
    }

    var requests: [OAuth2HTTPRequest] { lock.withLock { recorded } }

    func requests(to url: String) -> [OAuth2HTTPRequest] {
        let key = Self.key(URL(string: url)!)
        return requests.filter { Self.key($0.url) == key }
    }

    func send(_ request: OAuth2HTTPRequest) async throws -> OAuth2HTTPResponse {
        let response: OAuth2HTTPResponse? = lock.withLock {
            recorded.append(request)
            return routes[Self.key(request.url)]
        }
        guard let response else { throw OAuth2Error.network("no stub for \(Self.key(request.url))") }
        return response
    }

    private static func key(_ url: URL) -> String { "\(url.host ?? "")\(url.path)" }
}

/// Decodes an `application/x-www-form-urlencoded` body (`+` means space).
func formFields(_ body: Data?) -> [String: String] {
    var fields: [String: String] = [:]
    for pair in String(decoding: body ?? Data(), as: UTF8.self).split(separator: "&") {
        let parts = pair.replacingOccurrences(of: "+", with: " ")
            .split(separator: "=", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2,
              let key = String(parts[0]).removingPercentEncoding,
              let value = String(parts[1]).removingPercentEncoding else { continue }
        fields[key] = value
    }
    return fields
}

/// Query parameters of a URL; fails the lookup (returns nil) on a repeated name.
func queryParameters(_ url: URL) -> [String: String]? {
    let items = URLComponents(url: url, resolvingAgainstBaseURL: false)?.queryItems ?? []
    var result: [String: String] = [:]
    for item in items {
        if result[item.name] != nil { return nil }
        result[item.name] = item.value ?? ""
    }
    return result
}

func testConfiguration(
    transport: StubTransport,
    redirect: String = "https://app.test/auth/callback",
    scopes: [String]? = nil,
    usePKCE: Bool? = nil,
    secret: String? = "s3cr3t/+=&"
) -> OAuth2ClientConfiguration {
    OAuth2ClientConfiguration(
        clientID: "client id&x",
        clientSecret: secret,
        redirectURL: URL(string: redirect)!,
        scopes: scopes,
        usePKCE: usePKCE,
        http: OAuth2HTTPOptions(transport: transport)
    )
}

/// An unsigned compact JWT with the given payload.
func makeJWT(_ payload: [String: Any]) -> String {
    let header = base64URLEncode(Data(#"{"alg":"RS256","typ":"JWT"}"#.utf8))
    let body = base64URLEncode(try! JSONSerialization.data(withJSONObject: payload, options: [.sortedKeys]))
    return "\(header).\(body).c2lnbmF0dXJl"
}

let validState = String(repeating: "S", count: 43)

