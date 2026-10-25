import Foundation
#if canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(Darwin)
import Darwin
#endif

/// A tiny HTTP/1.1 server on 127.0.0.1 (ephemeral port) for exercising `URLSessionTransport`.
/// One thread per connection; each connection gets one response and is closed.
final class LocalHTTPServer: @unchecked Sendable {
    enum Behavior: Sendable {
        /// A complete response.
        case respond(status: Int, headers: [String: String], body: Data)
        /// Headers without a length, then body bytes until the client goes away.
        case endless
        /// `Content-Length: declared`, then one byte every `interval` seconds.
        case drip(declared: Int, interval: TimeInterval)
        /// Accepts and never answers.
        case silent
    }

    struct Received: Sendable {
        let head: String
        let body: Data
    }

    let port: UInt16
    private let listener: Int32
    // Guarded by `lock`.
    private let lock = NSLock()
    private var clients: [Int32] = []
    private var received: [Received] = []
    private var stopped = false
    private var bytesSent = 0
    private let behavior: @Sendable (Received) -> Behavior

    var requests: [Received] { lock.withLock { received } }
    var totalBytesSent: Int { lock.withLock { bytesSent } }
    var baseURL: String { "http://127.0.0.1:\(port)" }

    init(_ behavior: @escaping @Sendable (Received) -> Behavior) throws {
        self.behavior = behavior
        #if canImport(Darwin)
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        #else
        let fd = socket(AF_INET, Int32(SOCK_STREAM.rawValue), 0)
        #endif
        guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
        var one: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, socklen_t(MemoryLayout<Int32>.size))
        var address = sockaddr_in()
        #if canImport(Darwin)
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        #endif
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = 0
        address.sin_addr.s_addr = inet_addr("127.0.0.1")
        let bound = withUnsafePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size))
            }
        }
        guard bound == 0, listen(fd, 64) == 0 else {
            let code = POSIXErrorCode(rawValue: errno) ?? .EIO
            close(fd)
            throw POSIXError(code)
        }
        var length = socklen_t(MemoryLayout<sockaddr_in>.size)
        _ = withUnsafeMutablePointer(to: &address) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &length) }
        }
        listener = fd
        port = UInt16(bigEndian: address.sin_port)
        let thread = Thread { [self] in acceptLoop() }
        thread.start()
    }

    /// Idempotent, and never touches a descriptor this server no longer owns: closing the listener
    /// twice, or shutting down a client socket after its handler closed it, would hit whatever
    /// socket reused that number (another test's server or connection).
    func stop() {
        lock.withLock {
            if stopped { return }
            stopped = true
            // The accept thread notices `stopped` within one poll interval and closes the listener
            // itself, so no thread can accept() on a number that has been reused.
            // Handlers close their sockets under this lock, so these are still ours.
            for fd in clients { shutdown(fd, Int32(SHUT_RDWR)) }
        }
    }

    deinit { stop() }

    private func acceptLoop() {
        defer { close(listener) }
        while true {
            if lock.withLock({ stopped }) { return }
            var pfd = pollfd(fd: listener, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pfd, 1, 50)
            if ready < 0 && errno != EINTR { return }
            if ready <= 0 { continue }
            if lock.withLock({ stopped }) { return }
            let client = accept(listener, nil, nil)
            if client < 0 { continue }
            #if canImport(Darwin)
            var one: Int32 = 1
            setsockopt(client, SOL_SOCKET, SO_NOSIGPIPE, &one, socklen_t(MemoryLayout<Int32>.size))
            #endif
            let accepted: Bool = lock.withLock {
                if stopped { return false }
                clients.append(client)
                return true
            }
            guard accepted else { close(client); return }  // the deferred close(listener) follows
            Thread { [self] in handle(client) }.start()
        }
    }

    private func handle(_ fd: Int32) {
        defer {
            lock.withLock {
                clients.removeAll { $0 == fd }
                close(fd)
            }
        }
        guard let request = readRequest(fd) else { return }
        lock.withLock { received.append(request) }
        switch behavior(request) {
        case .respond(let status, let headers, let body):
            var head = "HTTP/1.1 \(status) Status\r\nContent-Length: \(body.count)\r\nConnection: close\r\n"
            for (name, value) in headers { head += "\(name): \(value)\r\n" }
            _ = write(fd, Data((head + "\r\n").utf8) + body)
        case .endless:
            guard write(fd, Data("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n".utf8)) else { return }
            let chunk = Data(repeating: UInt8(ascii: " "), count: 64 * 1024)
            while write(fd, chunk) {}
        case .drip(let declared, let interval):
            guard write(fd, Data("HTTP/1.1 200 OK\r\nContent-Length: \(declared)\r\nConnection: close\r\n\r\n".utf8)) else { return }
            for _ in 0..<declared {
                Thread.sleep(forTimeInterval: interval)
                if !write(fd, Data(" ".utf8)) { return }
            }
        case .silent:
            var byte: UInt8 = 0
            _ = recv(fd, &byte, 1, 0)  // returns when the client closes or the server stops
        }
    }

    private func write(_ fd: Int32, _ data: Data) -> Bool {
        if lock.withLock({ stopped }) { return false }
        #if canImport(Darwin)
        let flags: Int32 = 0
        #else
        let flags = Int32(MSG_NOSIGNAL)
        #endif
        return data.withUnsafeBytes { raw -> Bool in
            var offset = 0
            while offset < raw.count {
                let n = send(fd, raw.baseAddress! + offset, raw.count - offset, flags)
                if n <= 0 { return false }
                offset += n
                lock.withLock { bytesSent += n }
            }
            return true
        }
    }

    private func readRequest(_ fd: Int32) -> Received? {
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 4096)
        let separator = Data("\r\n\r\n".utf8)
        while buffer.range(of: separator) == nil {
            let n = recv(fd, &chunk, chunk.count, 0)
            if n <= 0 { return nil }
            buffer.append(chunk, count: n)
        }
        let split = buffer.range(of: separator)!
        let head = String(decoding: buffer[..<split.lowerBound], as: UTF8.self)
        var body = Data(buffer[split.upperBound...])
        let length = head.split(separator: "\r\n")
            .first { $0.lowercased().hasPrefix("content-length:") }
            .flatMap { Int($0.split(separator: ":")[1].trimmingCharacters(in: .whitespaces)) } ?? 0
        while body.count < length {
            let n = recv(fd, &chunk, chunk.count, 0)
            if n <= 0 { break }
            body.append(chunk, count: n)
        }
        return Received(head: head, body: body)
    }
}
