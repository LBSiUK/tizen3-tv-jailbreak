import sys, time; import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sdblib import Sdb
sdb = Sdb('192.168.0.85')
sdb.shell('0 vd_appuninstall xvvl3S1bvH', r'spend time', 60)
remote = '/home/owner/share/tmp/sdk_tools/tizenbrew.wgt'
sdb.push(remote, open(_os.path.join(_os.path.dirname(_os.path.abspath(__file__)), 'TizenBrewStandalone-Old.wgt'), 'rb').read())
out = sdb.shell('0 vd_appinstall xvvl3S1bvH ' + remote, r'spend time', 120)
print('install:', out.strip().splitlines()[-2])
print('launch:', sdb.shell('0 was_execute xvvl3S1bvH.TizenBrewStandalone', r'launched|resumed|spend time', 25).strip().splitlines()[-1])
