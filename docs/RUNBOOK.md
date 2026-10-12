# tierfs runbook

Read this before putting real files near tierfs. Status: the engines, the overlay, the daemon and the recovery tool are tested without a mount.
The FUSE-T mount layer is **unproven on real hardware**: see "Mount safety" below.

## Mount safety (read first)
FUSE-T serves a mount through macOS's own NFS client. On macOS 26.6.2 that client panicked the kernel (`nfs_vinvalbuf2: ubc_msync failed!`)
while `cp` wrote into a tierfs mount, and the machine reset several times during mount tests. Until the mount layer has been run in a throwaway
macOS VM without incident:
- do not mount tierfsd over real data;
- do not mount with unsaved work open;
- never `kill -9` a mounted driver or force-unmount it; stop it with `umount <mountpoint>` and wait for the process to exit.

## What you need before offloading anything
1. **A backup, recorded with its date** (see "Backups" below). tierfs refuses to move a file off the Mac unless it was created or last changed *before* the backup you recorded.
2. **The recovery phrase on paper.** It is the only way to get files back if this Mac is lost.
3. **At least two devices** (one copy is never enough: a file is only moved off the Mac once copies worth weight 2.0 passed a fresh audit).

## First-time setup
```bash
./build/tierctl init ~/tierfs-state/ledger --store keychain                   # shows the phrase once; you retype 3 groups; the key goes into the login Keychain
./build/tierctl check-phrase --store keychain ~/tierfs-state/ledger          # later: does my paper copy still match?
./build/tierctl check-backup ~/Folder                                        # read-only: what macOS says about Time Machine
./build/tierctl ack-backup ~/tierfs-state/ledger I-HAVE-A-BACKUP             # only after a real backup finished; records the TIME
```
The key is stored in your login Keychain, "this device only" (never synced to iCloud), under the service `tierfs-master-key` with the volume id as the account. The Keychain dies with the Mac, which is what the recovery phrase is for.
Tell the daemon with `keyfile=keychain`. macOS may ask once whether to allow access to the item.
Development alternatives: `--store dir:PATH` (one 0600 file per volume) or a plain key file (`tierctl init <ledger> <key-file>`, `keyfile=<key-file>`): neither is a secure store.
Keep the ledger directory on the internal disk and in your backups.

## Backups
tierfs never trusts itself with the only copy of a file, so before any file leaves the Mac you must state, with `ack-backup`, that a backup exists.
The statement is **dated**, and the rule is per file:
- a file may be moved only if it was created or last changed **before** the moment you recorded (so the backup holds this very version);
- a statement older than 30 days expires (`backup_max_age_days` in the ledger's meta changes it);
- after you edit or add files, back up again and re-run `ack-backup`; until then those files stay on the Mac (they are still copied to the devices).
`tierctl check-backup [folder]` reads what macOS says (destination, latest backup, whether the folder is excluded). It changes nothing and
may need Full Disk Access for your terminal; it cannot prove the backup contains a given file, which is why the statement stays yours.
Once files are offloaded they disappear from later backups of the folder: the older backups and the devices hold them.

## Devices
Start a device server on each storage device (another Mac, a NAS, a disk):
`./build/tierfs-device <store-dir> <port> <bind-address>`. It listens on loopback only unless you pass `--insecure-allow-network`
(there is no encryption on the wire; the data itself is encrypted and authenticated, but the protocol has no login). Do not expose it to a network
you do not control.

## Running the daemon (only after the mount-safety note is resolved)
```bash
./build/tierfsd -o origin=<real folder>,prefix=/Users/you/Folder/,ledger=<ledger dir>,keyfile=keychain,devices=host:port+host:port,namedattr,noappledouble <mountpoint>
```
- The mountpoint must not be the origin. To present files at their original path, move the real folder aside (same volume) and mount over the old path.
- Control it with `./build/tierctl control <ledger dir> status|scan|replicate PATH|offload PATH|hydrate PATH|undelete PATH|tick`.
- `launchd` (LaunchAgent) sketch, once the mount layer is trusted:
```xml
<plist version="1.0"><dict>
  <key>Label</key><string>local.tierfsd</string>
  <key>ProgramArguments</key><array><string>/path/to/tierfsd</string><string>-o</string><string>origin=...,prefix=...,ledger=...,keyfile=...,devices=...,namedattr,noappledouble</string><string>/path/to/mountpoint</string></array>
  <key>KeepAlive</key><false/>   <!-- do not auto-restart a crashed mount without looking at it -->
  <key>StandardErrorPath</key><string>/path/to/tierfsd.log</string>
</dict></plist>
```

## When something goes wrong
| Situation | What to do |
|---|---|
| The Mac is lost or the folder is gone | `tierctl restore --out <new folder> --device host:port [--device ...]` and type the phrase. Read-only towards the devices; never overwrites. Use `--dry-run` first. |
| A file looks wrong or missing | `tierctl control <ledger> status`, then `tierctl ledger-status <ledger>`; deleted files can be `undelete`d if they were offloaded; every version stays on the devices. |
| The daemon was killed mid-operation | Start it again: recovery finishes or undoes every interrupted drop, purge, restore and hydration before it serves anything. |
| A device is down | Local files and listings keep working; reading an offloaded file from it fails with an I/O error until a device with a good copy is back. |
| A device was restored from an old backup or re-initialised | It is marked suspect automatically and stops counting as a copy until every replica on it is re-audited. |
| "N of M tracked files are missing" | The folder is probably not mounted or the drive is disconnected. Nothing is forgotten. Reconnect it, or re-run `scan` with the guard relaxed only if you really deleted them. |
| macOS runs low on space | The policy plans which cold files to move and asks you; nothing is moved without a plan you approved (a consent that expires). |

## Tests (none of these mount anything)
`make test-unit test-client test-device test-replicator test-dropengine test-policy test-recovery test-overlay test-overlay-write test-overlay-ns test-scanner test-daemon`
plus `python3 -I tests/init_test.py`, and the TSan targets `test-ledger-tsan test-overlay-tsan test-ns-tsan`.
`scripts/phase3h-test.sh` mounts a real filesystem and refuses to run unless `TIERFS_I_ACCEPT_A_REBOOT=1`.
