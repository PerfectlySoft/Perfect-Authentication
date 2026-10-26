import Testing

/// Every suite that opens real sockets runs under this parent, one at a time: on Linux a URLSession
/// test leaves corelibs draining a cancelled body in the background, which on an emulated CPU can
/// starve whatever runs next to it.
@Suite("Transports", .serialized)
struct TransportSuites {}
