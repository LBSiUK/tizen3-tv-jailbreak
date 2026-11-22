import sys; import os as _os; sys.path.insert(0, _os.path.dirname(_os.path.abspath(__file__)))
from sdblib import Sdb
sdb = Sdb('192.168.0.85')
print(sdb.shell('0 was_execute xvvl3S1bvH.TizenBrewStandalone', r'launched|resumed|spend time', 25).strip().splitlines()[-1])
