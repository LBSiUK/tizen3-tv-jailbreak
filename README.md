# Tizen 3.0 TV jailbreak — in progress

Research repo for gaining root on a 2017 Samsung Smart TV. Not finished — root is **not** achieved yet; owner-level code execution is.

## Target

| | |
|---|---|
| Device | Samsung UE55MU7070 (2017, MU series) |
| OS | Tizen 3.0 |
| Kernel | Linux 4.1.10 armv7l (`Linux Samsung 4.1.10 #1 SMP PREEMPT`, gcc 4.9.2 Linaro) |
| Dev daemon | sdbd 3.2.5 (sdb 4.2.36 host side) |
| Dev mode | Developer Mode enabled on TV (sdb over TCP :26101) |

## Status

**Works:**
- Dev-signed `.wgt` / `.tpk` install + launch with **no Tizen Studio and no Samsung account** — the whole signing chain is reimplemented in Python (`signvar6.py`, `mktpk.py`), including the two XML-DSIG signatures with the `#prop` c14n11 reference that installs silently fail on otherwise (install fails with no error beyond `[118]` at 22%).
- A dependency-free sdb wire-protocol client (`sdblib.py`) — ADB framing over TCP :26101 with **byte-sum checksums** (not CRC32), talking to the sdbd 3.2.5 service whitelist: `getduid`, `vd_applist`, `vd_appinstall`, `vd_appuninstall`, `was_execute`, `was_kill`, `debug`, `rmfile`. Shell metacharacters are rejected; command injection into `vd_appinstall` filenames (backticks/`$()`) does not fire.
- Persistent code execution as `owner` (uid 5001) via a repacked TizenBrew module service (`tvroot-mod/service.js`): plaintext command channel on `:9192` (`tv-cmd '<shell command>'`), plus a beacon listener (`listener.py` on :9090) for out-of-band recon from a headless TV.

**Root leads (open):** see [analysis/wasutility.md](analysis/wasutility.md).

## Signing chain without Tizen Studio

1. **Author signature.** Samsung's own certificate-generator package (`certificate-generator_0.1.4` from download.tizen.org) ships the *Tizen Developers CA private key* (`certificates/developer/tizen-developer-ca-privatekey.pem`, password in `conf.ini`). With it you mint an author certificate with `basicConstraints=critical CA:FALSE`, `keyUsage=digitalSignature`, EKU `codeSigning` (`authext.cnf`).
2. **Distributor signature.** Sample distributor PKCS12 from Samsung/WATT sample-certs (`tizen-distributor-signer.p12`).
3. **The `#prop` gotcha.** `author-signature.xml` and `signature1.xml` must carry a `Reference URI="#prop"` with Transform `http://www.w3.org/2006/12/xml-c14n11`. Python lxml **cannot produce c14n11** (its inclusive c14n differs). The correct `DigestValue` is structure-only and identical across packages — copy it verbatim from any known-good wgt (e.g. a free-my-tv release). The constants are in `signvar6.py` (`PROP_DIGEST`).
4. **Zip layout.** `author-signature.xml` first, `signature1.xml` last, payload files alphabetical, URI paths percent-encoded (`%2F`).

Multiple different authors install fine — there is no author pin. Everything is accepted by `vd_appinstall` over sdb.

## Repo layout

```
sdblib.py          sdb wire-protocol client (ADB framing, byte-sum checksum)
install*.py        push + vd_appinstall/was_execute drivers
postwake.py        full post-wake probe matrix (recon, wasutility, exec-mmap, attack installs)
postreset.py       anchor install + traversal probe install
signvar*.py        wgt signer iterations (6 = current), signtrav*.py traversal variants
mktpk.py / mkwgt*.py  tpk/wgt builders
tvrootd.c          C daemon payload: beacon + popen cmd channel :9292
tvroot-mod/        TizenBrew module replacement service (recon + cmd channel :9192)
localsvc/          replacement StandaloneService for the anchor wgt
tpk/               tpk payload tree (tvrootd binary)
tvprobe            static ARMv7 exec-mmap probe binary
wasutility.bin     copy of the TV's setuid-root /usr/bin/wasutility (for analysis)
analysis/          reverse-engineering notes
os-release, version, mounts, passwd, pkglist.txt, changelog, pkginfo.manifest — device evidence
step1-4.sh         early dockerized official-sdb probes
tv.sh, tv-cmd      helpers
```

Private keys (`*.key`, `*.p12`) and the large third-party archives (WATT, certificate-generator, Certificate-Manager, the sdb binary) are **not** committed — fetch them yourself (see sources below) and drop them next to the scripts.

## Resume point

TV on → `listener.py` (beacons) → `postwake.py`:
kdbus/env recon, exec-mmap matrix (`/run/user/5001`, `/dev/shm` vs the known-bad `/opt`, `/tmp`), `wasutility` option surface as uid 5001, pulls of `wrt-installer` / `pkgcmd` / `libwrt-tmg-settings.so`, and installs of the pending attack packages (`wgttrav.wgt` zip-traversal markers, `wgtsym.wgt` symlink plant).

Destructive sdbd-side actions (`wasutility -w/-r`, `sdb rmfile`) are deliberately not scripted.

- Samsung certificate-generator + Certificate-Manager: download.tizen.org
- Distributor sample certs: Samsung/WATT sample-certs
- [TizenBrew](https://github.com/reisxd/TizenBrew) (GPL-3.0) — the module-service anchor is a repack of it; `wgtvar.wgt` embeds its build
- free-my-tv release wgt — reference for known-good signature digests
- SamyGo — the ancestral Samsung-TV hacking effort

Research on hardware I own, for interoperability and security study. No warranty; a wrong move (especially `wasutility --clear-all`, factory reset paths, or `sdb rmfile`) can wipe app registrations or brick the set.
