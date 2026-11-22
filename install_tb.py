import sys; import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sdblib import Sdb
sdb = Sdb('192.168.0.85')
remote = '/home/owner/share/tmp/sdk_tools/tizenbrew.wgt'
sdb.push(remote, open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'TizenBrewStandalone-Old.wgt'), 'rb').read())
print('pushed')
out = sdb.shell('0 vd_appinstall xvvl3S1bvH ' + remote, r'spend time', 120)
print('INSTALL TIZENBREW:', out.strip())
if 'install completed' in out:
    print('LAUNCH:', sdb.shell('0 was_execute xvvl3S1bvH.TizenBrewStandalone', r'launched|spend time|end', 25).strip())
