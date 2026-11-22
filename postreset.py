import sys, json, time; import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sdblib import Sdb
sdb = Sdb('192.168.0.85')
# 1. anchor: install wgtvar (TizenBrew machinery under MY sigs)
r = '/home/owner/share/tmp/sdk_tools/wgtvar.wgt'
sdb.push(r, open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'wgtvar.wgt'), 'rb').read())
out = sdb.shell('0 vd_appinstall w9test0001 ' + r, r'spend time', 120)
print('ANCHOR wgtvar:', 'OK' if 'install completed' in out else out.strip()[-150:])
if 'install completed' in out:
    print('launch:', sdb.shell('0 was_execute w9test0001.ProbeApp', r'launched|resumed', 25).strip().splitlines()[-1])
# 2. traversal probe
r2 = '/home/owner/share/tmp/sdk_tools/wgttrav.wgt'
sdb.push(r2, open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'wgttrav.wgt'), 'rb').read())
out2 = sdb.shell('0 vd_appinstall leonbtrav1 ' + r2, r'spend time', 120)
print('TRAV:', 'OK' if 'install completed' in out2 else out2.strip()[-150:])
