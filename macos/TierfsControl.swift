// The menu-bar app's side of tierfsd's control socket (core/daemon.hpp): one line in, a few lines out, the last of which is "OK" or "ERR <reason>".
// No user interface in this file, so the whole of it can be tested against a stand-in server (macos/tests/control_test.swift).
import Foundation

public enum ControlError: Error, Equatable, CustomStringConvertible {
    case noSocket(String)       // tierfsd is not running (or this is not its ledger directory)
    case connectFailed(String)
    case timedOut
    case tooLarge
    case ioFailed(String)
    public var description: String {
        switch self {
        case .noSocket(let p): return "tierfsd is not running here (no control socket at \(p))"
        case .connectFailed(let m): return "cannot connect to tierfsd: \(m)"
        case .timedOut: return "tierfsd did not answer in time"
        case .tooLarge: return "tierfsd sent an absurdly large answer"
        case .ioFailed(let m): return "talking to tierfsd failed: \(m)"
        }
    }
}

public struct ControlReply: Equatable {
    public let lines: [String]   // everything before the final OK / ERR line
    public let ok: Bool          // the final line was OK
    public let error: String     // the reason after ERR (empty when ok)
    public var text: String { lines.joined(separator: "\n") }
}

public func parseReply(_ raw: String) -> ControlReply {
    var lines = raw.components(separatedBy: "\n")
    while let last = lines.last, last.isEmpty { lines.removeLast() }
    guard let final = lines.last else { return ControlReply(lines: [], ok: false, error: "no answer") }
    if final == "OK" { return ControlReply(lines: Array(lines.dropLast()), ok: true, error: "") }
    if final.hasPrefix("ERR") {
        let reason = final.dropFirst(3).trimmingCharacters(in: .whitespaces)
        return ControlReply(lines: Array(lines.dropLast()), ok: false, error: reason.isEmpty ? "refused" : reason)
    }
    return ControlReply(lines: lines, ok: false, error: "the answer did not end with OK or ERR")   // an old or confused daemon: shown, never trusted
}

public final class ControlClient {
    public let socketPath: String
    public static let maxReply = 4 << 20

    public init(socketPath: String) { self.socketPath = socketPath }
    public convenience init(ledgerDir: String) { self.init(socketPath: (ledgerDir as NSString).appendingPathComponent("control.sock")) }

    /// Sends one command and returns the answer. `timeout` is for the whole exchange.
    public func send(_ command: String, timeout: TimeInterval = 60) throws -> ControlReply {
        guard FileManager.default.fileExists(atPath: socketPath) else { throw ControlError.noSocket(socketPath) }
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        if fd < 0 { throw ControlError.connectFailed(String(cString: strerror(errno))) }
        defer { close(fd) }
        var noSigPipe: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &noSigPipe, socklen_t(MemoryLayout<Int32>.size))
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let maxLen = MemoryLayout.size(ofValue: addr.sun_path)
        let bytes = Array(socketPath.utf8)
        if bytes.count >= maxLen { throw ControlError.connectFailed("the socket path is too long") }
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: UInt8.self, capacity: maxLen) { dst in
                for (i, b) in bytes.enumerated() { dst[i] = b }
                dst[bytes.count] = 0
            }
        }
        let rc = withUnsafePointer(to: &addr) { p in
            p.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) }
        }
        if rc != 0 { throw ControlError.connectFailed(String(cString: strerror(errno))) }

        let deadline = Date().addingTimeInterval(timeout)
        // the command is one line: never let a newline in it become a second command
        let line = command.replacingOccurrences(of: "\n", with: " ").replacingOccurrences(of: "\r", with: " ") + "\n"
        let out = Array(line.utf8)
        var sent = 0
        while sent < out.count {
            let n = out.withUnsafeBufferPointer { write(fd, $0.baseAddress! + sent, out.count - sent) }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { throw ControlError.ioFailed(String(cString: strerror(errno))) }
            sent += n
        }
        var data = Data()
        var buf = [UInt8](repeating: 0, count: 65536)
        while true {
            let left = deadline.timeIntervalSinceNow
            if left <= 0 { throw ControlError.timedOut }
            var p = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let pr = poll(&p, 1, Int32(min(left * 1000, 1_000_000)))
            if pr < 0 && errno == EINTR { continue }
            if pr < 0 { throw ControlError.ioFailed(String(cString: strerror(errno))) }
            if pr == 0 { throw ControlError.timedOut }
            let n = read(fd, &buf, buf.count)
            if n < 0 && errno == EINTR { continue }
            if n < 0 { throw ControlError.ioFailed(String(cString: strerror(errno))) }
            if n == 0 { break }   // the daemon closes the connection after its answer
            data.append(buf, count: n)
            if data.count > ControlClient.maxReply { throw ControlError.tooLarge }
        }
        return parseReply(String(decoding: data, as: UTF8.self))
    }
}

// MARK: what the answers say

public enum SpaceLevel: String { case ok = "OK", low = "LOW", critical = "CRITICAL", unknown = "?" }

public struct SpaceReport: Equatable {
    public let level: SpaceLevel
    public let headline: String      // "25.0 GiB free of 200.0 GiB"
    public let detail: [String]      // the rest of the report, one line each
    public let problem: String?      // "PROBLEM: ..." (for instance, notifications cannot be shown)
}

/// `space` answers "Space LOW: 25.0 GiB free of 200.0 GiB." first, then details (see format_space in core/policy.cpp).
public func parseSpace(_ reply: ControlReply) -> SpaceReport? {
    guard reply.ok, let first = reply.lines.first, first.hasPrefix("Space ") else { return nil }
    let afterSpace = first.dropFirst("Space ".count)
    guard let colon = afterSpace.firstIndex(of: ":") else { return nil }
    let level = SpaceLevel(rawValue: String(afterSpace[afterSpace.startIndex..<colon])) ?? .unknown
    var headline = afterSpace[afterSpace.index(after: colon)...].trimmingCharacters(in: .whitespaces)
    if headline.hasSuffix(".") { headline.removeLast() }
    var detail: [String] = [], problem: String? = nil
    for l in reply.lines.dropFirst() {
        let t = l.trimmingCharacters(in: .whitespaces)
        if t.isEmpty { continue }
        if t.hasPrefix("PROBLEM:") { problem = String(t.dropFirst("PROBLEM:".count)).trimmingCharacters(in: .whitespaces) } else { detail.append(t) }
    }
    return SpaceReport(level: level, headline: headline, detail: detail, problem: problem)
}

public struct PlanReview: Equatable {
    public let id: String              // the plan id to approve (16 hex characters)
    public let text: String            // what a person reads
    public let hasFiles: Bool          // the plan moves something (it offers an approval)
    public let blocked: Bool           // "CANNOT RUN YET:" is in it: approving would be refused
    public var canApprove: Bool { hasFiles && !blocked }
}

/// `plan` answers "SPACE PLAN <id>" first. A plan with nothing to do, or "Disk space is fine ...", has no id to approve.
public func parsePlan(_ reply: ControlReply) -> PlanReview? {
    guard reply.ok else { return nil }
    let text = reply.text
    guard let first = reply.lines.first, first.hasPrefix("SPACE PLAN ") else { return nil }
    let id = String(first.dropFirst("SPACE PLAN ".count)).trimmingCharacters(in: .whitespaces)
    let hex = Set("0123456789abcdef")
    guard id.count == 16, id.allSatisfy({ hex.contains($0) }) else { return nil }
    return PlanReview(id: id, text: text, hasFiles: text.contains("This plan moves "), blocked: text.contains("CANNOT RUN YET:"))
}

public struct DeviceLine: Equatable {
    public let spec: String
    public let state: String   // "attached 1a2b3c4d", "not attached", "at host:port, not attached", ...
}

/// `status` has one "device <spec> <state>" line per device.
public func parseDevices(_ reply: ControlReply) -> [DeviceLine] {
    reply.lines.compactMap { l in
        guard l.hasPrefix("device ") else { return nil }
        let rest = l.dropFirst("device ".count)
        guard let sp = rest.firstIndex(of: " ") else { return DeviceLine(spec: String(rest), state: "") }
        return DeviceLine(spec: String(rest[rest.startIndex..<sp]), state: String(rest[rest.index(after: sp)...]))
    }
}

/// An id typed or taken from text is only ever sent if it is 16 hex characters: nothing else reaches the socket as an approval.
public func approveCommand(forPlanID id: String) -> String? {
    let hex = Set("0123456789abcdef")
    return id.count == 16 && id.allSatisfy({ hex.contains($0) }) ? "approve \(id)" : nil
}
