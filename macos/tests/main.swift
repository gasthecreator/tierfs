// Tests of the menu-bar app's control client (macos/TierfsControl.swift) against a stand-in for tierfsd's control socket.
import Foundation

signal(SIGPIPE, SIG_IGN)   // (the stand-in server writes to clients that have already given up)
var failures = 0
func check(_ cond: @autoclosure () -> Bool, _ what: String, line: Int = #line) {
    if cond() { print("PASS  \(what)") } else { print("FAIL  line \(line): \(what)"); failures += 1 }
}

// ---- a stand-in server: each connection reads one line, records it, answers with what the handler says (or nothing), then closes
final class FakeDaemon {
    let path: String
    private var listenFD: Int32 = -1
    private let lock = NSLock()
    private var received: [String] = []
    var handler: (String) -> (reply: Data?, hold: TimeInterval) = { _ in (Data("OK\n".utf8), 0) }
    private var running = true

    init() {
        path = NSTemporaryDirectory() + "tfs\(getpid())-\(Int.random(in: 0..<1_000_000)).sock"
        unlink(path)
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        withUnsafeMutablePointer(to: &addr.sun_path) { p in
            p.withMemoryRebound(to: UInt8.self, capacity: 104) { dst in
                for (i, b) in bytes.enumerated() { dst[i] = b }
                dst[bytes.count] = 0
            }
        }
        _ = withUnsafePointer(to: &addr) { p in p.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size)) } }
        listen(listenFD, 8)
        Thread.detachNewThread { [self] in
            while running {
                let c = accept(listenFD, nil, nil)
                if c < 0 { break }
                Thread.detachNewThread { [self] in serve(c) }
            }
        }
    }
    private func serve(_ c: Int32) {
        var line = Data()
        var ch: UInt8 = 0
        while read(c, &ch, 1) == 1, ch != 10 { line.append(ch) }
        let cmd = String(decoding: line, as: UTF8.self)
        lock.lock(); received.append(cmd); lock.unlock()
        let (reply, hold) = handler(cmd)
        if hold > 0 { Thread.sleep(forTimeInterval: hold) }
        if let r = reply {
            var off = 0
            r.withUnsafeBytes { raw in
                while off < r.count {
                    let n = write(c, raw.baseAddress! + off, r.count - off)
                    if n <= 0 { break }
                    off += n
                }
            }
        }
        close(c)
    }
    var commands: [String] { lock.lock(); defer { lock.unlock() }; return received }
    func stop() { running = false; close(listenFD); unlink(path) }
}

// ---- parseReply
do {
    check(parseReply("a\nb\nOK\n") == ControlReply(lines: ["a", "b"], ok: true, error: ""), "an answer ending in OK")
    check(parseReply("OK\n") == ControlReply(lines: [], ok: true, error: ""), "a bare OK")
    check(parseReply("ERR there is no plan to approve: run plan first\n") == ControlReply(lines: [], ok: false, error: "there is no plan to approve: run plan first"), "ERR with its reason")
    check(parseReply("some text\nERR\n").error == "refused" && !parseReply("some text\nERR\n").ok, "a bare ERR is still a refusal")
    check(parseReply("line\nOK\n\n\n").ok, "blank lines after OK are ignored")
    let odd = parseReply("space OK\nand more\n")
    check(!odd.ok && odd.error.contains("did not end"), "an answer without OK or ERR is never trusted")
    check(parseReply("").error == "no answer" && !parseReply("").ok, "no answer at all")
    check(parseReply("OK is in the middle\nERR but not at the end\nOK\n").ok, "OK and ERR inside text do not matter, only the last line")
    check(!parseReply("OK\nERR late\n").ok, "the LAST line decides")
    check(!parseReply("OK \n").ok, "OK with a trailing space is not OK")
}

// ---- the client against the stand-in
do {
    let d = FakeDaemon()
    defer { d.stop() }
    d.handler = { cmd in (Data("echo: \(cmd)\nOK\n".utf8), 0) }
    let c = ControlClient(socketPath: d.path)
    let r = try? c.send("plan free-now 20")
    check(r?.ok == true && r?.lines == ["echo: plan free-now 20"], "a command goes out and the answer comes back")
    check(d.commands == ["plan free-now 20"], "the daemon received exactly that line")
    _ = try? c.send("approve abc\nstatus")
    check(d.commands.last == "approve abc status", "a newline in a command cannot become a second command")
    _ = try? c.send("a\rb")
    check(d.commands.last == "a b", "nor can a carriage return")
    // large answers
    d.handler = { _ in (Data((String(repeating: "x", count: 1_000_000) + "\nOK\n").utf8), 0) }
    check((try? c.send("big"))?.ok == true, "a megabyte answer arrives whole")
    d.handler = { _ in (Data(String(repeating: "y", count: 5 << 20).utf8), 0) }
    do { _ = try c.send("huge"); check(false, "an absurdly large answer is refused") } catch { check((error as? ControlError) == .tooLarge, "an absurdly large answer is refused") }
    // silence
    d.handler = { _ in (nil, 3) }
    let t0 = Date()
    do { _ = try c.send("slow", timeout: 0.4); check(false, "a daemon that stays silent times out") } catch { check((error as? ControlError) == .timedOut && Date().timeIntervalSince(t0) < 2.5, "a daemon that stays silent times out") }
    // a daemon that closes without answering
    d.handler = { _ in (nil, 0) }
    let silent = try? c.send("hang up")
    check(silent?.ok == false && silent?.error == "no answer", "a daemon that hangs up gives \"no answer\", not OK")
    // an answer that arrives in pieces
    d.handler = { _ in (Data("part one\n".utf8), 0.1) }
    check((try? c.send("pieces"))?.ok == false, "an answer cut off before OK is not accepted")
    // nobody there
    do { _ = try ControlClient(socketPath: d.path + ".nope").send("status"); check(false, "no socket") } catch {
        check((error as? ControlError) == .noSocket(d.path + ".nope"), "no socket file: tierfsd is not running")
        check("\(error)".contains("not running"), "and it says so")
    }
    // a socket file nobody listens on
    let dead = NSTemporaryDirectory() + "dead\(getpid()).sock"
    FileManager.default.createFile(atPath: dead, contents: nil)
    defer { unlink(dead) }
    do { _ = try ControlClient(socketPath: dead).send("status"); check(false, "a dead socket file") } catch {
        if case ControlError.connectFailed = error { check(true, "a file that is not a listening socket: cannot connect") } else { check(false, "a file that is not a listening socket: cannot connect") }
    }
    // a path too long for a unix socket
    let long = NSTemporaryDirectory() + String(repeating: "a", count: 120) + ".sock"
    FileManager.default.createFile(atPath: long, contents: nil)
    defer { unlink(long) }
    do { _ = try ControlClient(socketPath: long).send("status"); check(false, "a path that is too long") } catch {
        if case ControlError.connectFailed(let m) = error { check(m.contains("too long"), "a path that is too long is refused plainly") } else { check(false, "a path that is too long is refused plainly") }
    }
    check(ControlClient(ledgerDir: "/x/y").socketPath == "/x/y/control.sock" && ControlClient(ledgerDir: "/x/y/").socketPath == "/x/y/control.sock", "the socket lives in the ledger directory")
}

// ---- reading the daemon's answers (the texts are the ones core/policy.cpp and core/daemon.cpp produce)
do {
    let space = parseReply("""
    Space LOW: 25.0 GiB free of 200.0 GiB.
      warns below 30.0 GiB free, critical below 10.0 GiB; a plan aims for 37.5 GiB.
      12.5 GiB would have to move off this Mac to reach the target.
      Last notified: LOW at 2026-10-16 09:00
      Checked every 30 seconds; notifications are on.
      PROBLEM: the low-space notification could not be shown (is a user session logged in?); it will be tried again
    OK

    """)
    let s = parseSpace(space)
    check(s?.level == .low && s?.headline == "25.0 GiB free of 200.0 GiB" && s?.detail.count == 4 && s?.problem?.hasPrefix("the low-space notification") == true, "the space report is read")
    check(s?.detail.first?.hasPrefix("warns below") == true, "details are trimmed")
    check(parseSpace(parseReply("Space OK: 100.0 GiB free of 200.0 GiB.\n  You have not been notified about low space.\nOK\n"))?.level == .ok, "normal space")
    check(parseSpace(parseReply("Space CRITICAL: 3.0 GiB free of 200.0 GiB.\nOK\n"))?.level == .critical, "critical space")
    check(parseSpace(parseReply("Space ODD: 3 GiB free of 200 GiB.\nOK\n"))?.level == .unknown, "an unknown level is shown as unknown, not guessed")
    check(parseSpace(parseReply("ERR no\n")) == nil && parseSpace(parseReply("garbage\nOK\n")) == nil && parseSpace(parseReply("Space nothing\nOK\n")) == nil, "anything else is not a space report")
    check(parseSpace(parseReply("Space LOW: 1 GiB free\nERR something\n")) == nil, "a refusal is never a report")

    let id = "0123456789abcdef"
    let good = parsePlan(parseReply("SPACE PLAN \(id)\n\nDisk: 25.0 GiB free of 200.0 GiB (LOW). 12.5 GiB should be freed.\n\nThis plan moves 3 files (13.0 GiB) off this Mac:\n\nTo approve exactly this plan (good for 60 minutes):\n  tierctl control 'x' approve \(id)\nOK\n"))
    check(good?.id == id && good?.hasFiles == true && good?.blocked == false && good?.canApprove == true, "a plan that can be approved")
    let blocked = parsePlan(parseReply("SPACE PLAN \(id)\n\nThis plan moves 3 files (13.0 GiB) off this Mac:\n\nCANNOT RUN YET:\n  - no backup is recorded\n\nFix the above, then approve with:\n  tierctl approve \(id)\nOK\n"))
    check(blocked?.canApprove == false && blocked?.blocked == true && blocked?.hasFiles == true, "a plan with something in the way cannot be approved from here")
    let empty = parsePlan(parseReply("SPACE PLAN \(id)\n\nNo file can be moved: nothing in your tiered folders is cold, big and safe enough.\nOK\n"))
    check(empty?.canApprove == false && empty?.hasFiles == false, "a plan with nothing in it cannot be approved")
    check(parsePlan(parseReply("Disk space is fine (100.0 GiB free of 200.0 GiB): nothing needs to move. To plan anyway: plan <GiB to free>\nOK\n")) == nil, "plenty of space: no plan")
    check(parsePlan(parseReply("SPACE PLAN 0123\nOK\n")) == nil && parsePlan(parseReply("SPACE PLAN 0123456789ABCDEF\nOK\n")) == nil && parsePlan(parseReply("SPACE PLAN 0123456789abcdeg\nOK\n")) == nil, "a malformed id is never accepted")
    check(parsePlan(parseReply("SPACE PLAN \(id)\nERR trouble\n")) == nil, "a refused plan is not a plan")

    check(approveCommand(forPlanID: id) == "approve \(id)", "the approval for a good id")
    for bad in ["", "0123", id + "0", "0123456789ABCDEF", "0123456789abcde;", "0123456789abcde\n", "../../etc/passwd/x", " 123456789abcdef"] {
        check(approveCommand(forPlanID: bad) == nil, "no approval for \"\(bad.replacingOccurrences(of: "\n", with: "\\n"))\"")
    }

    let devs = parseDevices(parseReply("""
    volume 8b3d2f881f192fcb3c081c1ee556d263
    files REPLICATED 1
    device 127.0.0.1:9571@053991c37fa34571 attached 1a2b3c4d
    device mdns:kitchen-pi@053991c37fa34571 at 192.168.1.20:9100, not attached
    device 127.0.0.1:9572 not attached
    devicex not a device line
    note something
    OK

    """))
    check(devs.count == 3 && devs[0].spec == "127.0.0.1:9571@053991c37fa34571" && devs[0].state == "attached 1a2b3c4d" &&
          devs[1].state == "at 192.168.1.20:9100, not attached" && devs[2] == DeviceLine(spec: "127.0.0.1:9572", state: "not attached"), "the device lines are read")
    check(parseDevices(parseReply("device lonely\nOK\n")) == [DeviceLine(spec: "lonely", state: "")], "a device line without a state")
    check(parseDevices(parseReply("OK\n")).isEmpty, "no devices")
}

print(failures == 0 ? "\nALL PASSED (0 failures)" : "\nFAILED (\(failures) failures)")
exit(failures == 0 ? 0 : 1)
