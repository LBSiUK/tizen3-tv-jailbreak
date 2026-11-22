S=/w/data/tools/sdb
$S connect 192.168.0.85:26101 >/dev/null
echo "== pull round-trip of pushed file =="
$S -s 192.168.0.85:26101 pull /tmp/test.tpk /tmp/back.tpk 2>&1 | tail -2
echo "== /etc/os-release =="
$S -s 192.168.0.85:26101 pull /etc/os-release /w/os-release 2>&1 | tail -1 && cat /w/os-release 2>/dev/null
echo "== /etc/passwd =="
$S -s 192.168.0.85:26101 pull /etc/passwd /w/passwd 2>&1 | tail -1 && cat /w/passwd 2>/dev/null
echo "== /proc/version =="
$S -s 192.168.0.85:26101 pull /proc/version /w/version 2>&1 | tail -1 && cat /w/version 2>/dev/null
echo "== /proc/mounts =="
$S -s 192.168.0.85:26101 pull /proc/mounts /w/mounts 2>&1 | tail -1 && head -25 /w/mounts 2>/dev/null
echo "== dlog (5s sample) =="
timeout 5 $S -s 192.168.0.85:26101 dlog 2>&1 | head -15
