func digIntoDictionary(mineFor: [String], data: [String: Any]) -> Any {
    if mineFor.isEmpty { return "" }
    for (key, value) in data {
        if key == mineFor[0] {
            var remaining = mineFor
            remaining.removeFirst()
            if remaining.isEmpty {
                return value
            } else if let nested = value as? [String: Any] {
                return digIntoDictionary(mineFor: remaining, data: nested)
            }
        }
    }
    return ""
}
