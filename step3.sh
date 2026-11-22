S=/w/data/tools/sdb
$S connect 192.168.0.85:26101 >/dev/null
cd /tmp
touch test.tpk
touch 'test.tpk`sleep${IFS}10`.tpk'
touch 'test.wgt`sleep${IFS}10`.wgt'
echo "== sync service probe: push =="
$S -s 192.168.0.85:26101 push test.tpk /tmp/ 2>&1 | head -3
echo "== install baseline (plain name, garbage pkg) =="
time $S -s 192.168.0.85:26101 install test.tpk </dev/null 2>&1 | head -5
echo "== install tpk payload name =="
time $S -s 192.168.0.85:26101 install 'test.tpk`sleep${IFS}10`.tpk' </dev/null 2>&1 | head -5
echo "== install wgt payload name =="
time $S -s 192.168.0.85:26101 install 'test.wgt`sleep${IFS}10`.wgt' </dev/null 2>&1 | head -5
