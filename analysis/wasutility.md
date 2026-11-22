# /usr/bin/wasutility — setuid-root attack surface

Copy of the on-device binary: `wasutility.bin` (32-bit ARM Thumb, dynamically linked,
stripped; build path `/home/abuild/rpmbuild/BUILD/org.tizen.webappservice-0.1/src/Tool/AppRecoveryTool.cpp`).

One of only three setuid-root binaries on the TV:

```
/usr/bin/wasutility
/usr/lib/chromium-efl/chrome-sandbox
/usr/lib/dbus/dbus-daemon-launch-helper
```

Our app context (uid 5001) has CapEff=0 but CapBnd=0x3fffffffff, Seccomp: none reported in /proc/self/status.

## CLI surface

`getopt_long` short string: **`wu:v:a:d:g:f:re:cnm:`**; long options observed: `--clear-all`, `--clear-wrt-database`.

| opt | handler (log tag) | what it does as root |
|---|---|---|
| `-w` | `wrt_clear` | `invoke_wrt_installer_recovery_mode` → vfork + `execve(wrt-installer)` |
| `-u <appid>` | `wrt_uninstall` | execve wrt-installer with `-un <appid>` — **appid is argv, attacker-controlled** |
| `-f <appid>` | `wrt_force_uninstall` | same with `-fun <appid>` |
| `-r` | `wrt_reset_userdata_all` | execve **`/pkgcmd --clear-all wgt`** — wipes all web-app registrations (destructive) |
| `-a <appid>` | `wrt_active` | `WRT::TMGSettings::Activate(appid, …)` in libwrt-tmg-settings.so |
| `-d <appid>` | `wrt_deactive` | `WRT::TMGSettings::Deactivate(appid)` |
| `-c` | `wrt_clear_wrt_database` | `remove()` on `.webappservice.db{,-journal}`, `create_new_db()` |
| `-v -g -e -n -m` | ? | unidentified — probe on device |
| (other) | `remove_dir` | fixed dirs `/emanual/`, `/emanual_icon/`, `/demo_movie/`, `/Welcome_Movie/`, `/webappservice/preinstall/`; logs `REMOVE pkg_path=[%s], realPath=[%s]` and `realpath()`-guards |

`create_new_db()` (0x1298d): sqlite3_open `/opt/dbspace/.webappservice.db`, executes SQL from
tzplatform path `/org.tizen.webappservice/data/AppsDB.conf`, then execve's `/bin/chown owner:users`
and `/bin/chsmack … User::App::Shared` with `PATH=/bin` on the recreated DB — i.e. a root-owned
DB ends up chowned `owner:users` (plant target).

## The environment bug (main lead)

`main()` (0x150f8) `putenv`s, before anything else:

```
DBUS_SESSION_BUS_ADDRESS=kdbus:path=/dev/kdbus/%U-kdbus/bus
DBUS_SYSTEM_BUS_ADDRESS=kdbus:path=/dev/kdbus/0-kdbus-system/bus
```

The `%U` is a **literal** in the binary (rodata 0x16ee8) — no expansion happens in-process.
Every root child exec'd by wasutility (wrt-installer, pkgcmd) inherits it.

Why it matters: setuid-root semantics give the children `uid=0, euid=0, ruid=5001`.
If Tizen's D-Bus/kdbus client stack expands `%U` via the **real** uid (the usual
session-bus convention), the root child connects to `/dev/kdbus/5001-kdbus/bus` — a bus
endpoint owned by the unprivileged user. Whoever answers there receives privileged D-Bus
traffic (app install/uninstall/launch requests from wrt-installer & pkgmgr).

Open questions (device off, untested):
1. does anything on-device expand `%U`, and via ruid or euid?
2. can uid 5001 create/own a kdbus endpoint (`/sys/fs/kdbus/control` is mounted, kdbusfs `nosuid,nodev,noexec`)?
3. what session-bus address do *running* app processes actually carry (`/proc/<pid>/environ`)?

## execve plumbing

`invoke_wrt_installer_recovery_mode` (0x125a4, called from 5 sites in `wasutility_process_request`):
builds a `std::vector<std::string>` whose `[0]` is `tzplatform_getenv(…) + "/wrt-installer"`
(rodata: `"/wrt-installer"`, `"-un"`, `"-fun"`), `putenv("PATH=…")`, vfork, child does
`execve(vec[0], vec, envp)` — waitpid in parent. On failure: `Execve return error = [%s]`.

Next analysis step: pull `/usr/bin/wrt-installer`, `/usr/bin/pkgcmd`,
`/usr/lib/libwrt-tmg-settings.so.0.1.0` (postwake.py step 5) and check whether the
attacker-controlled appid reaches `execve`/`system()`/path-concat sinks inside them, or
SQLite string-building (sqlite3_exec injection → `ATTACH DATABASE` file write as root).

## Related root-side surfaces (unprobed)

- sdbd whitelist includes `debug` and `rmfile` — both execute as the sdbd process (root).
  `0 debug` argument format unknown; a root-side debugserver would be immediate game over.
- Kernel 4.1.10 (SMP, armv7, no KPTI era) — DirtyCow-class n-days apply **iff** we can
  exec our own binary; exec-mmap from `/opt` (vdfs4) and `/tmp` failed with
  "failed to map segment from shared object". `/run/user/5001` and `/dev/shm` (tmpfs,
  `nosuid,nodev`, no `noexec`) are untested.
