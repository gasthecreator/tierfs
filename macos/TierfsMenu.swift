// A menu-bar app for tierfs: how much room is left, what could move, and a button to approve exactly the plan you read.
// It only talks to tierfsd's control socket (TierfsControl.swift); everything it shows is what the daemon said, and the only thing it can do is send
// `plan` and `approve <id>`. The daemon still enforces every rule (recovery phrase, backup statement, two devices, fresh audits) when a plan runs.
//
//   TierfsMenu [--ledger DIR]        DIR is the ledger directory given to tierfsd (default: ~/.tierfs/ledger)
import AppKit

@main
final class TierfsMenu: NSObject, NSApplicationDelegate {
    private var item: NSStatusItem!
    private var client: ControlClient!
    private var space: SpaceReport?
    private var devices: [DeviceLine] = []
    private var unreachable: String?
    private var timer: Timer?
    private let work = DispatchQueue(label: "tierfs.menu.poll")
    private var review: ReviewWindow?

    static func main() {
        let app = NSApplication.shared
        let delegate = TierfsMenu()
        app.delegate = delegate
        app.setActivationPolicy(.accessory)   // a menu-bar item only: no Dock icon
        app.run()
    }

    func applicationDidFinishLaunching(_ n: Notification) {
        var ledger = (NSHomeDirectory() as NSString).appendingPathComponent(".tierfs/ledger")
        let args = CommandLine.arguments
        if let i = args.firstIndex(of: "--ledger"), i + 1 < args.count { ledger = (args[i + 1] as NSString).expandingTildeInPath }
        client = ControlClient(ledgerDir: ledger)
        item = NSStatusBar.system.statusItem(withLength: NSStatusItem.variableLength)
        render()
        poll()
        timer = Timer.scheduledTimer(withTimeInterval: 15, repeats: true) { [weak self] _ in self?.poll() }
    }

    private func poll() {
        work.async { [self] in
            var report: SpaceReport?, devs: [DeviceLine] = [], down: String?
            do {
                report = parseSpace(try client.send("space", timeout: 10))
                devs = parseDevices(try client.send("status", timeout: 10))
            } catch { down = "\(error)" }
            DispatchQueue.main.async {
                self.space = report
                self.devices = devs
                self.unreachable = down
                self.render()
            }
        }
    }

    private func render() {
        let menu = NSMenu()
        func add(_ title: String, enabled: Bool = false, action: Selector? = nil) {
            let it = NSMenuItem(title: title, action: action, keyEquivalent: "")
            it.target = self
            it.isEnabled = enabled
            menu.addItem(it)
        }
        var title = "tierfs"
        if let down = unreachable {
            title += " · off"
            add(down)
        } else if let s = space {
            if s.level != .ok { title += " · \(s.level.rawValue)" }
            add("Space \(s.level.rawValue): \(s.headline)")
            for d in s.detail.prefix(4) { add(d) }
            if let p = s.problem { add("Problem: \(p)") }
        } else {
            add("Waiting for tierfsd…")
        }
        menu.addItem(.separator())
        add("Review what could move…", enabled: unreachable == nil, action: #selector(openReview))
        if !devices.isEmpty {
            menu.addItem(.separator())
            for d in devices { add("Device \(d.spec): \(d.state)") }
        }
        menu.addItem(.separator())
        add("Quit", enabled: true, action: #selector(quit))
        item.button?.title = title
        item.menu = menu
    }

    @objc private func openReview() {
        if review == nil { review = ReviewWindow(client: client) }
        review?.show()
    }

    @objc private func quit() { NSApp.terminate(nil) }
}

/// The plan, in the daemon's own words, and one button: approve exactly this plan.
final class ReviewWindow: NSObject, NSWindowDelegate {
    private let client: ControlClient
    private let window: NSWindow
    private let text = NSTextView()
    private let approve = NSButton(title: "Approve this plan", target: nil, action: nil)
    private var current: PlanReview?

    init(client: ControlClient) {
        self.client = client
        window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 640, height: 520), styleMask: [.titled, .closable, .resizable], backing: .buffered, defer: false)
        super.init()
        window.title = "tierfs: what could move"
        window.delegate = self
        window.isReleasedWhenClosed = false
        let scroll = NSScrollView(frame: NSRect(x: 0, y: 48, width: 640, height: 472))
        scroll.autoresizingMask = [.width, .height]
        scroll.hasVerticalScroller = true
        text.isEditable = false
        text.font = NSFont.monospacedSystemFont(ofSize: 12, weight: .regular)
        text.autoresizingMask = [.width]
        scroll.documentView = text
        let refresh = NSButton(title: "Look again", target: self, action: #selector(reload))
        refresh.frame = NSRect(x: 12, y: 10, width: 110, height: 28)
        approve.target = self
        approve.action = #selector(confirmApprove)
        approve.frame = NSRect(x: 440, y: 10, width: 188, height: 28)
        approve.autoresizingMask = [.minXMargin]
        approve.isEnabled = false
        window.contentView?.addSubview(scroll)
        window.contentView?.addSubview(refresh)
        window.contentView?.addSubview(approve)
    }

    func show() {
        window.center()
        NSApp.activate(ignoringOtherApps: true)
        window.makeKeyAndOrderFront(nil)
        reload()
    }

    @objc private func reload() {
        text.string = "Asking tierfsd…"
        approve.isEnabled = false
        current = nil
        DispatchQueue.global().async { [self] in
            let shown: String, plan: PlanReview?
            do {
                let reply = try client.send("plan", timeout: 120)
                plan = parsePlan(reply)
                shown = reply.ok ? reply.text : "tierfsd refused: \(reply.error)"
            } catch { shown = "\(error)"; plan = nil }
            DispatchQueue.main.async {
                self.text.string = shown
                self.current = plan
                self.approve.isEnabled = plan?.canApprove ?? false   // blocked plans and plans with nothing in them cannot be approved from here
            }
        }
    }

    @objc private func confirmApprove() {
        guard let plan = current, plan.canApprove, let command = approveCommand(forPlanID: plan.id) else { return }
        let alert = NSAlert()
        alert.messageText = "Move these files off this Mac?"
        alert.informativeText = "This is exactly the plan you have just read (\(plan.id)). Each file is copied to at least two devices and checked again before it moves, and stays visible at the same path."
        alert.addButton(withTitle: "Approve")
        alert.addButton(withTitle: "Cancel")
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        approve.isEnabled = false
        text.string = "Running the plan… this can take a while (files may have to be copied first)."
        DispatchQueue.global().async { [self] in
            let shown: String
            do {
                let reply = try client.send(command, timeout: 3600)
                shown = reply.ok ? reply.text : "tierfsd refused: \(reply.error)\n\n\(reply.text)"
            } catch { shown = "\(error)" }
            DispatchQueue.main.async { self.text.string = shown }
        }
    }

    func windowWillClose(_ n: Notification) { current = nil }
}
