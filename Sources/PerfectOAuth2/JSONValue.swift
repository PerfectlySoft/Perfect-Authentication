import Foundation

/// A Sendable JSON value, used for provider responses (`OAuthUserProfile.raw`).
public enum JSONValue: Sendable, Equatable, Hashable, Codable {
    case null
    case bool(Bool)
    case integer(Int64)
    case double(Double)
    case string(String)
    case array([JSONValue])
    case object([String: JSONValue])

    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        if container.decodeNil() {
            self = .null
        } else if let value = try? container.decode(Bool.self) {
            self = .bool(value)
        } else if let value = try? container.decode(Int64.self) {
            self = .integer(value)
        } else if let value = try? container.decode(Double.self) {
            self = .double(value)
        } else if let value = try? container.decode(String.self) {
            self = .string(value)
        } else if let value = try? container.decode([JSONValue].self) {
            self = .array(value)
        } else if let value = try? container.decode([String: JSONValue].self) {
            self = .object(value)
        } else {
            throw DecodingError.dataCorruptedError(in: container, debugDescription: "Not a JSON value")
        }
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .integer(let value): try container.encode(value)
        case .double(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }

    /// Parses JSON data. Throws `OAuth2Error.invalidResponse` if it isn't JSON.
    public init(data: Data) throws {
        do {
            self = try JSONDecoder().decode(JSONValue.self, from: data)
        } catch {
            throw OAuth2Error.invalidResponse("response is not JSON")
        }
    }

    /// The member named `key` if this is an object.
    public subscript(key: String) -> JSONValue? {
        if case .object(let object) = self { return object[key] }
        return nil
    }

    public var stringValue: String? {
        if case .string(let value) = self { return value }
        return nil
    }

    public var boolValue: Bool? {
        switch self {
        case .bool(let value): return value
        // Some providers send "true"/"false" as strings (e.g. older id_token email_verified).
        case .string("true"): return true
        case .string("false"): return false
        default: return nil
        }
    }

    public var int64Value: Int64? {
        switch self {
        case .integer(let value): return value
        case .double(let value):
            guard value.rounded() == value, abs(value) < 9.2e18 else { return nil }
            return Int64(value)
        case .string(let value): return Int64(value)
        default: return nil
        }
    }

    public var doubleValue: Double? {
        switch self {
        case .integer(let value): return Double(value)
        case .double(let value): return value
        case .string(let value): return Double(value)
        default: return nil
        }
    }

    public var objectValue: [String: JSONValue]? {
        if case .object(let value) = self { return value }
        return nil
    }

    public var arrayValue: [JSONValue]? {
        if case .array(let value) = self { return value }
        return nil
    }

    /// A string or integer identifier as a string (GitHub user ids are numbers, most others strings).
    public var identifierValue: String? {
        switch self {
        case .string(let value): return value
        case .integer(let value): return String(value)
        default: return nil
        }
    }
}
