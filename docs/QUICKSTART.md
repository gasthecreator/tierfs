# Quickstart: from nothing to a working setup

Read the status first: the engines, the overlay, the daemon, the recovery tool, the Android agent and the menu-bar app are tested without a mount. **The FUSE-T mount layer has never been proven on
real hardware** (it once reset the development Mac), so this page takes you as far as is safe and says where you stop. The full reference is [RUNBOOK.md](RUNBOOK.md).

## 1. Build
```bash
brew install openssl@3 sqlite          # FUSE-T (https://github.com/macos-fuse-t/fuse-t) is needed only to build and run the mount driver tierfsd
make                                    # ./build/tierctl, ./build/tierfs-device, ./build/tierfsd, ...
make test                               # about 15 minutes; mounts nothing
```

## 2. A volume, its recovery phrase and a backup statement
```bash
./build/tierctl init ~/tierfs-state/ledger --store keychain          # shows the recovery phrase ONCE; write it on paper; retype three groups to prove it
./build/tierctl check-backup ~/Folder                                # what macOS says about Time Machine (read-only)
./build/tierctl ack-backup ~/tierfs-state/ledger I-HAVE-A-BACKUP     # only after a real backup finished: it records the time
```
Without the phrase, a lost Mac means lost files. Without a backup statement, tierfs will not move a file off the Mac.

## 3. Two devices (one is never enough)
On each device (another Mac, a NAS, a Raspberry Pi, a phone):
```bash
./build/tierfs-device ~/tierfs-device-store --add-pairing="my MacBook"              # prints a code and a key id; add --pairing-allow-delete if this Mac may clean up old versions there
./build/tierfs-device ~/tierfs-device-store 9100 0.0.0.0 --advertise=kitchen-pi     # serves; paired devices only listen on the network; --advertise lets Macs find it by name
```
For a phone: build the APK ([../android/README.md](../android/README.md)), switch it on, and show its pairing code. On the Mac:
```bash
./build/tierctl pair <device address>:9100 --store keychain           # type the code; the device and the Mac prove they hold the same secret
./build/tierctl discover --store keychain                              # lists devices announcing themselves, and the entry to use for each
```

## 4. Tell the daemon about them, and start it (only with throwaway files until the mount layer is proven)
```bash
./build/tierfsd -o origin=<real folder>,prefix=/Users/you/Folder/,ledger=$HOME/tierfs-state/ledger,keyfile=keychain,devices=mdns:kitchen-pi@<keyid>+<host>:9100@<keyid>,namedattr,noappledouble <mountpoint>
./build/tierctl control ~/tierfs-state/ledger status                  # which devices are attached, how much space is left
```
`tierctl service plist|install` makes this a LaunchAgent; `macos/build.sh` builds the menu-bar app that shows the same status and the plan below.

## 5. What happens when the disk fills
tierfs warns you (every 30 seconds it checks; `tierctl space <ledger>` shows the numbers) and **never moves anything by itself**:
```bash
./build/tierctl plan ~/tierfs-state/ledger                            # the plan in plain words: what moves, what is left alone, what is in the way
./build/tierctl approve ~/tierfs-state/ledger <plan id>               # runs exactly that plan, once, while it is fresh
```
Offloaded files stay at the same path; opening one fetches it back. The bytes stay on the Mac, set aside, for 7 days after a move (you can undo until then).

## 6. Prove the safety net before you trust it
- **Recovery drill**: `tierctl restore --out /tmp/drill --device <host:port>@<keyid> --store keychain --dry-run`, then without `--dry-run`. If this works with the phrase alone, a lost Mac is survivable.
- **Revoke a Mac**: `tierfs-device <store> --list-pairings`, then `--revoke-pairing=<key id>`: that Mac is refused at once.
- **Undo a garbage collection**: a device keeps what it deleted for 7 days (`--list-trash`, `--restore-trash`). Garbage collection itself is off unless you turn it on (`gc=1`).
- Run `tierctl ledger-status ~/tierfs-state/ledger` after any trouble: it checks the ledger's own integrity.

## Where you must stop
- Do not mount tierfs over files you cannot lose until it has run in a throwaway macOS VM without incident ([RUNBOOK.md](RUNBOOK.md), "Mount safety").
- A phone is a poor only copy; tierfs keeps at least two verified copies before a file leaves the Mac, but a lost phone costs you one of them.
