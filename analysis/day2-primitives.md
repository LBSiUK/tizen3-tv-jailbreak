# Day-2 findings (2026-11-23): primitives, walls, and the current frontier

## Proven primitives

### 1. Dev signing WORKS for fresh installs
`signvar6.py`-signed wgts install and complete (tested with a minimal app, `leonbmin1`).
Same-chain comparison with the proven-installable TizenBrew original: identical CA
structure (`Tizen Developers CA` author chain, `Tizen Public Distributor Signer`
distributor chain). Notes:

- Update-in-place fast-fails `[118]` when the new package's **author cert differs**
  from the installed record (`/opt/dbspace/.pkgmgr_cert.db`, see below) — that is an
  author-consistency guard, not a signature failure.
- The full TizenBrew content re-signed under a fresh pkgid fails `[118]` at **82%**
  (late stage, content/privilege-specific — matches upstream reisxd/TizenBrew#239).

### 2. Arbitrary file write as `app_fw` via absolute-path zip entries  ← the big one
A wgt whose zip contains entries with **absolute paths** (`/opt/usr/home/owner/travH`,
`/run/systemd/system/pwn.service`) gets them **extracted by the installer running as
`app_fw`** before validation aborts the install (`[118]` at 16%).

- The written file persists — **no rollback**.
- Content, mode (0644 tested) controlled by us; owner `app_fw:app_fw`.
- Writable targets proven: `/opt/usr/home/owner/**`, `/tmp/**`, **`/run/systemd/system/**`**.
- `..` traversal entries: rejected outright (all URI encodings tried).
- Zip symlink entries: extracted literally, write-through does NOT escape.

### 3. Planted systemd units load but cannot start
`/run/systemd/system/pwn.service` planted via (2); `Manager.LoadUnit` (policy-allowed)
shows `LoadState=loaded`. But **every mutating Manager call** (`StartUnit`,
`StartTransientUnit`, `Reload`, …) returns `AccessDenied` — Samsung's kdbus policy
translation tightens the stock `systemd1.conf` (which textually allows Start* for
everyone). D-Bus activation doesn't map: `BusName=` units planted this way never
register an activator (needs a real daemon-reload; lazy load is not enough).

### 4. World-writable package DBs
`/opt/dbspace/.pkgmgr_cert.db` (and `-journal`) are **0666** (`tizenglobalapp`).
Schema: `package_cert_info(package, author/dist cert ids)` + `package_cert_index_info(cert_id, base64 cert)`.
Poisoning an author-cert row would let our packages pass the update-in-place
author-consistency guard for any pkgid → install-over a partner app → inherit its
privileges/labels. (Not yet executed.)

## Walls (measured, not assumed)

- **No native code, anywhere.** Copying `/bin/true` to `/tmp` (or any writable fs) and
  exec'ing it → `EPERM` (Operation not permitted), even from the `User` Smack label,
  even though mounts show no `noexec` and `User → User::Pkg::X = rwxat` rules exist.
  Same hook blocks `mmap PROT_EXEC` (yesterday's `.node` addon failures). DirtyCow,
  kernel modules via `ps_insmod`, pepper-plugin `.so` replacement — all dead unless
  the file carries a label/property the hook accepts (untested: a file labeled
  `System`; unreachable for us so far since file labels follow the creating process).
- **`ps_insmod` / `ps_mknod` have empty policy tables** → deny-all. `ps_mount`'s table
  (dumped from rodata-in-.text) is (label-regex, caller-exe, argv-regex) triples; the
  `/usr/bin/node` entry allows ANY label but requires the **sender process exe** to be
  node — spawned helpers (gdbus/dbus-send) fail it, and node 4.4.3 cannot speak
  kdbus (ioctls). Member name: `SendMessage`, args `(s, i)` (from
  `libprivileged-service-client.so` disasm, included here).
- **System bus policy**: broad introspection + `Properties.Get` allowed; everything
  mutating denied for uid 5001.

## Context notes

- Session-bus (`/sys/fs/kdbus/5001-user/`, ours) carries proxied root services
  (hbbtv `IDownloadManager` et al., pid 356/888/889…, all GDBus 2.44.1, introspectable)
  and a **user systemd** (units run as uid 5001, label `User`; `User=0` → exit 216).
  Full introspection dumps of the hbbtv tree are easy if that surface becomes
  interesting.
- `~/.config/systemd/user/` units + `StartUnit` on the **user** manager work (arbitrary
  uid-5001 commands at will) — same power as the TizenBrew module channel.
- `wasutility`'s `%U` session-bus env lead is dead on this model: `/dev/kdbus` doesn't
  exist; real session bus is `kernel:path=/sys/fs/kdbus/5001-user/bus`.
- Smack rules: installed app labels `User::Pkg::<id>` get `rwxat` on
  `User::Author::<n>` files; our author cert maps to `User::Author::2`.
- `unpack-XXXXXXXX` temp dirs under `apps_rw/` (hundreds, app_fw-only) are the
  installer's scratch areas.

## Next leads (ranked)

1. **Poison `.pkgmgr_cert.db` (666) → install-over a partner-privileged pkgid** →
   partner privileges (pkgmgr admin) → deeper install flows (tpk, service units) that
   trigger real `systemctl daemon-reload`-equivalent behavior in root contexts.
2. Find any root-side `daemon-reload`/restart trigger reachable from us (factory
   service `org.tizen.tv.factory-service` `/TIFacSerObj` — no introspection; binary
   hunt pending; classic SamyGo territory).
3. Determine the exec hook's exact check (label vs signature) — if label-based, a
   `System`-labeled file we can influence anywhere changes everything.
4. hbbtv root-daemon method audit (download manager, PVR record paths).
