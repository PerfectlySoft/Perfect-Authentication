import Foundation
#if canImport(FoundationNetworking)
import FoundationNetworking
#endif

enum HTTPVerb { case get, post }

func urlencode(dict: [String: String]) -> String {
    dict.map { key, value in
        "\(key.urlEncoded)=\(value.urlEncoded)"
    }.joined(separator: "&")
}

extension OAuth2 {
    func makeRequest(
        _ method: HTTPVerb,
        _ url: String,
        body: String = "",
        encoding: String = "JSON",
        bearerToken: String = ""
    ) async -> [String: Any] {
        guard let requestURL = URL(string: url) else { return [:] }
        var request = URLRequest(url: requestURL)
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        request.setValue("no-cache", forHTTPHeaderField: "Cache-Control")
        request.setValue("PerfectAPI2.0", forHTTPHeaderField: "User-Agent")

        if !bearerToken.isEmpty {
            request.setValue("Bearer \(bearerToken)", forHTTPHeaderField: "Authorization")
        }

        if method == .post {
            request.httpMethod = "POST"
            request.httpBody = body.data(using: .utf8)
            let contentType = encoding == "form"
                ? "application/x-www-form-urlencoded"
                : "application/json"
            request.setValue(contentType, forHTTPHeaderField: "Content-Type")
        }

        do {
            let (data, _) = try await URLSession.shared.data(for: request)
            guard let obj = try? JSONSerialization.jsonObject(with: data) else { return [:] }
            if let dict = obj as? [String: Any] { return dict }
            if let arr = obj as? [Any] { return ["response": arr] }
            return [:]
        } catch {
            return [:]
        }
    }
}
