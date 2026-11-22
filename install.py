import sys, time
import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sdblib import Sdb
sdb = Sdb('192.168.0.85')
remote = '/home/owner/share/tmp/sdk_tools/tvroot.wgt'
data = open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'tvroot.wgt'), 'rb').read()
sdb.push(remote, data)
print('pushed %d bytes' % len(data))
out = sdb.shell('0 vd_appinstall leonbroot1 ' + remote, r'spend time', 120)
print('INSTALL:', out.strip())
if 'install completed' in out:
    out2 = sdb.shell('0 was_execute leonbroot1.Probe', r'launched|spend time|end', 25)
    print('LAUNCH:', out2.strip())
