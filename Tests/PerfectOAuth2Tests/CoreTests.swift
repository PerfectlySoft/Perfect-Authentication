import Foundation
import Testing
@testable import PerfectOAuth2

@Suite("State (CSRF)")
struct StateTests {
    @Test func generatedStateIsLongRandomBase64URL() {
        let a = AuthorizationState.generate(), b = AuthorizationState.generate()
        #expect(a.count == 43)
        #expect(a != b)
        #expect(a.allSatisfy { $0.isLetter || $0.isNumber || $0 == "-" || $0 == "_" })
        #expect(base64URLDecode(a)?.count == 32)
    }

    @Test func matchingStatePasses() throws {
        let state = AuthorizationState.generate()
        try AuthorizationState.verify(returned: state, expected: state)
    }

    @Test func emptyStatesAreRejected() {
        // 1.x accepted state "" against a session value "".
        #expect(throws: OAuth2Error.invalidState("stored state must be at least 32 characters")) {
            try AuthorizationState.verify(returned: "", expected: "")
        }
        #expect(throws: OAuth2Error.stateMismatch) {
            try AuthorizationState.verify(returned: "", expected: validState)
        }
        #expect(throws: OAuth2Error.stateMismatch) {
            try AuthorizationState.verify(returned: nil, expected: validState)
        }
    }

    @Test func shortOrHugeStoredStateIsRejected() {
        let short = String(repeating: "a", count: 31)
        #expect(throws: OAuth2Error.self) { try AuthorizationState.verify(returned: short, expected: short) }
        let huge = String(repeating: "a", count: 513)
        #expect(throws: OAuth2Error.self) { try AuthorizationState.verify(returned: huge, expected: huge) }
        let ok = String(repeating: "a", count: 32)
        #expect(throws: Never.self) { try AuthorizationState.verify(returned: ok, expected: ok) }
    }

    @Test func mismatchesAreRejected() {
        let state = AuthorizationState.generate()
        var flipped = Array(state)
        flipped[flipped.count - 1] = flipped.last == "A" ? "B" : "A"
        for returned in [String(flipped), state + "x", String(state.dropLast()), state.uppercased() == state ? "x" : state.uppercased()] {
            #expect(throws: OAuth2Error.stateMismatch) {
                try AuthorizationState.verify(returned: returned, expected: state)
            }
        }
    }

    @Test func constantTimeCompare() {
        #expect(constantTimeEquals("", ""))
        #expect(constantTimeEquals("abc", "abc"))
        #expect(!constantTimeEquals("abc", "abd"))
        #expect(!constantTimeEquals("abc", "abc\u{0}"))
        #expect(!constantTimeEquals("abc", "ab"))
        #expect(constantTimeEquals("é", "é"))
    }
}

@Suite("PKCE and encoding")
struct PKCETests {
    @Test func rfc7636AppendixBVector() {
        #expect(PKCE.challenge(for: "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk")
            == "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
    }

    @Test func verifierMeetsRFC7636() {
        let verifier = PKCE.generateVerifier()
        #expect((43...128).contains(verifier.count))
        #expect(verifier.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || "-._~".contains($0)) })
        #expect(PKCE.generateVerifier() != verifier)
        #expect(PKCE.challenge(for: verifier).count == 43)
    }

    @Test func base64URLRoundTripAndRejection() {
        for length in 0..<70 {
            let data = Data((0..<length).map { UInt8(truncatingIfNeeded: $0 &* 37 &+ 250) })
            let encoded = base64URLEncode(data)
            #expect(!encoded.contains("=") && !encoded.contains("+") && !encoded.contains("/"))
            #expect(base64URLDecode(encoded) == data)
        }
        #expect(base64URLDecode("_-8") == Data([0xFF, 0xEF]))
        #expect(base64URLDecode("+/8=") == nil)   // standard alphabet
        #expect(base64URLDecode("abcde") == nil)  // impossible length
        #expect(base64URLDecode("ab$d") == nil)
    }

    @Test func facebookAppSecretProofIsHMACSHA256() {
        // RFC 4231 test case 2: key "Jefe", data "what do ya want for nothing?".
        #expect(Facebook.appSecretProof(accessToken: "what do ya want for nothing?", appSecret: "Jefe")
            == "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
    }

    @Test func formEncodingEncodesEverythingReserved() {
        let body = String(decoding: formEncode([("a b", "x+y/z=&?%é"), ("k", "")]), as: UTF8.self)
        #expect(body == "a%20b=x%2By%2Fz%3D%26%3F%25%C3%A9&k=")
    }

    @Test func appendingQueryItemsEncodesPlusAndAmpersand() throws {
        let url = try appendingQueryItems(
            [URLQueryItem(name: "v", value: "a+b&c=d e")],
            to: URL(string: "https://h.test/p?x=1")!
        )
        #expect(url.absoluteString == "https://h.test/p?x=1&v=a%2Bb%26c%3Dd%20e")
    }
}

@Suite("Token parsing")
struct TokenTests {
    @Test func parsesStandardResponse() throws {
        let now = Date(timeIntervalSince1970: 1_000_000)
        let token = try OAuth2Token(json: JSONValue(data: Data("""
            {"access_token":"AT","token_type":"Bearer","expires_in":3600,"refresh_token":"RT","scope":"openid email"}
            """.utf8)), now: now)
        #expect(token.accessToken == "AT")
        #expect(token.refreshToken == "RT")
        #expect(token.expiresIn == 3600)
        #expect(token.expiration == now.addingTimeInterval(3600))
        #expect(token.scope == ["openid", "email"])
    }

    @Test func expiresInAsStringOrDouble() throws {
        for raw in [#""3599""#, "3599", "3599.0"] {
            let token = try OAuth2Token(json: JSONValue(data: Data(#"{"access_token":"a","expires_in":\#(raw)}"#.utf8)))
            #expect(token.expiresIn == 3599)
        }
        for raw in [#""soon""#, "-5", "1e30", "null"] {
            let token = try OAuth2Token(json: JSONValue(data: Data(#"{"access_token":"a","expires_in":\#(raw)}"#.utf8)))
            #expect(token.expiresIn == nil)
            #expect(token.expiration == nil)
        }
    }

    @Test func scopeDelimiters() throws {
        let github = try OAuth2Token(json: JSONValue(data: Data(#"{"access_token":"a","scope":"repo,gist"}"#.utf8)))
        #expect(github.scope == ["repo", "gist"])
        let spaced = try OAuth2Token(json: JSONValue(data: Data(#"{"access_token":"a","scope":"a  b, c"}"#.utf8)))
        #expect(spaced.scope == ["a", "b", "c"])
        let empty = try OAuth2Token(json: JSONValue(data: Data(#"{"access_token":"a","scope":""}"#.utf8)))
        #expect(empty.scope == [])
    }

    @Test func requiresNonEmptyAccessToken() {
        for body in [#"{}"#, #"{"access_token":""}"#, #"{"access_token":5}"#] {
            #expect(throws: OAuth2Error.self) { try OAuth2Token(json: JSONValue(data: Data(body.utf8))) }
        }
    }

    @Test func defaultsAndEmptyRefreshToken() throws {
        let token = try OAuth2Token(json: JSONValue(data: Data(#"{"access_token":"a","token_type":"","refresh_token":""}"#.utf8)))
        #expect(token.tokenType == "Bearer")
        #expect(token.refreshToken == nil)
    }
}

@Suite("JSONValue")
struct JSONValueTests {
    @Test func decodesAllKinds() throws {
        let json = try JSONValue(data: Data(#"{"s":"x","i":9007199254740993,"d":1.5,"b":true,"n":null,"a":[1,"2"],"o":{"k":"v"}}"#.utf8))
        #expect(json["s"] == .string("x"))
        #expect(json["i"]?.identifierValue == "9007199254740993")
        #expect(json["d"]?.doubleValue == 1.5)
        #expect(json["b"]?.boolValue == true)
        #expect(json["n"] == .null)
        #expect(json["a"]?.arrayValue?.count == 2)
        #expect(json["o"]?["k"]?.stringValue == "v")
        #expect(json["missing"] == nil)
        #expect(json["s"]?["k"] == nil)
    }

    @Test func rejectsNonJSON() {
        #expect(throws: OAuth2Error.invalidResponse("response is not JSON")) {
            try JSONValue(data: Data("<html>".utf8))
        }
    }
}

@Suite("Profile")
struct ProfileTests {
    @Test func emptyUserIDIsRejected() {
        let token = OAuth2Token(accessToken: "a")
        for id in [nil, "", "  ", "\n"] as [String?] {
            #expect(throws: OAuth2Error.missingUserID) {
                try OAuthUserProfile(userid: id, loginType: "x", token: token)
            }
        }
    }

    @Test func emailVerifiedNeedsAnEmail() throws {
        let profile = try OAuthUserProfile(userid: "1", email: "", emailVerified: true, loginType: "x", token: OAuth2Token(accessToken: "a"))
        #expect(profile.email == nil)
        #expect(profile.emailVerified == false)
    }
}

@Suite("Callback parsing")
struct CallbackTests {
    @Test func readsCodeStateAndError() {
        let ok = AuthorizationCallback(url: URL(string: "https://app.test/cb?code=a%2Bb&state=s%26t")!)
        #expect(ok.code == "a+b")
        #expect(ok.state == "s&t")
        #expect(ok.error == nil)
        let denied = AuthorizationCallback(url: URL(string: "https://app.test/cb?error=access_denied&error_description=User%20said%20no&state=x")!)
        #expect(denied.error?.standardCode == .accessDenied)
        #expect(denied.error?.errorDescription == "User said no")
    }

    @Test func repeatedParametersAreIgnored() {
        let callback = AuthorizationCallback(url: URL(string: "https://app.test/cb?code=a&code=b&state=s&state=t")!)
        #expect(callback.code == nil)
        #expect(callback.state == nil)
    }
}
