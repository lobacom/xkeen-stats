#!/usr/bin/env bash
# Запускается только на одноразовом Linux runner GitHub Actions.
set -euo pipefail
test "${GITHUB_ACTIONS:-}" = true
test "$(id -u)" = 0
for path in /opt/bin/sh /opt/etc/xkeen-stats /opt/etc/xray /opt/var/lib/xkeen-stats /opt/sbin/xkeen-stats /opt/sbin/xray /opt/etc/init.d/rc.func; do
  test ! -e "$path" || { echo "Fixture path already exists: $path" >&2; exit 1; }
done
task_tmp=$(mktemp -d)
cleanup() {
  for file in /opt/var/run/xkeen-stats-fixture.pid /opt/var/run/xray-fixture.pid; do
    if test -f "$file"; then kill "$(cat "$file")" 2>/dev/null || true; fi
  done
  ip link delete xkstest 2>/dev/null || true
  rm -rf /opt/etc/xkeen-stats /opt/etc/xray /opt/var/lib/xkeen-stats
  rm -f /opt/bin/sh /opt/sbin/xkeen-stats /opt/sbin/xray /opt/bin/iptables /opt/etc/init.d/rc.func /opt/etc/init.d/S05xkeen /opt/etc/init.d/S99xkeen-stats /opt/etc/ndm/netfilter.d/051-xkeen-stats-lan.sh /opt/var/run/xkeen-stats-fixture.pid /opt/var/run/xray-fixture.pid
  rm -rf -- "$task_tmp"
}
trap cleanup EXIT
trap 'echo "Installer fixture failed: ${mode:-initialization}" >&2; for log in "$task_tmp"/*.log; do test ! -f "$log" || grep -Ei "failed|error|fatal|cannot" "$log" >&2 || true; done' ERR
mkdir -p /opt/bin /opt/sbin /opt/etc/init.d /opt/etc/ndm/netfilter.d /opt/var/run
ln -s /bin/sh /opt/bin/sh
go build -o /opt/sbin/xray ./.github/test-xray
go build -ldflags='-X main.version=v0.5.0-dev' -o "$task_tmp/installer" .
ip link add xkstest type dummy
ip address add 10.222.0.1/24 dev xkstest
ip link set xkstest up
cat >/opt/bin/iptables <<'EOF'
#!/bin/sh
[ "${1:-}" = -w ] || exit 3
shift
case "$1" in -C|-nL) exit 1;; esac
case " $* " in *' REJECT '*) case " $* " in *' -p tcp '*) ;; *) exit 2;; esac;; esac
exit 0
EOF
cat >/opt/etc/init.d/rc.func <<'EOF'
stats_pid=/opt/var/run/xkeen-stats-fixture.pid
case "$1" in
  start) /opt/sbin/xkeen-stats > /opt/var/run/xkeen-stats-fixture.log 2>&1 & echo $! > "$stats_pid";;
  stop) if test -f "$stats_pid"; then kill "$(cat "$stats_pid")" 2>/dev/null || true; sleep 1; rm -f "$stats_pid"; fi;;
esac
EOF
chmod 700 /opt/bin/iptables
for mode in single split; do
  mkdir -p /opt/etc/xray/configs
  cat >/opt/etc/xray/configs/01.json <<'EOF'
{"inbounds":[{"tag":"users","protocol":"vless","settings":{"clients":[{"email":"fixture","id":"00000000-0000-4000-8000-000000000001"}]}}],"outbounds":[{"tag":"vpn","protocol":"vless","settings":{"vnext":[{"address":"127.0.0.1","port":10085}]}}],"routing":{"rules":[]},"policy":{"levels":{"0":{"handshake":8}}}}
EOF
  if test "$mode" = split; then
    echo '{"log":{"loglevel":"warning"}}' >/opt/etc/xray/configs/02.json
    config_option='-confdir /opt/etc/xray/configs'
  else
    config_option='-config /opt/etc/xray/configs/01.json'
  fi
  cat >/opt/etc/init.d/S05xkeen <<EOF
#!/bin/sh
if test -f /opt/var/run/xray-fixture.pid; then kill "\$(cat /opt/var/run/xray-fixture.pid)" 2>/dev/null || true; sleep 1; fi
/opt/sbin/xray run $config_option >/opt/var/run/xray-fixture.log 2>&1 &
echo \$! >/opt/var/run/xray-fixture.pid
EOF
  chmod 700 /opt/etc/init.d/S05xkeen
  /opt/etc/init.d/S05xkeen start
  common=(-interface xkstest -listen 10.222.0.1:11001 -lan 10.222.0.0/24)
  "$task_tmp/installer" -install-plan "${common[@]}" > "$task_tmp/plan.json"
  test ! -e /opt/etc/xkeen-stats/service.json
  "$task_tmp/installer" -install "${common[@]}" -allow-xray-restart > "$task_tmp/install.log" 2>&1
  python3 - <<'PY' > "$task_tmp/setup.json"
import json,pathlib
print(json.dumps(dict(token=pathlib.Path('/opt/etc/xkeen-stats/setup-token').read_text(),password='fixture-password-123',confirm_password='fixture-password-123')))
PY
  curl --noproxy '*' -fsS -H 'Content-Type: application/json' -H 'Origin: http://10.222.0.1:11001' -d @"$task_tmp/setup.json" -c "$task_tmp/cookies" http://10.222.0.1:11001/auth/setup > "$task_tmp/setup-result.json"
  curl --noproxy '*' -fsS -b "$task_tmp/cookies" http://10.222.0.1:11001/api/stats > "$task_tmp/stats.json"
  python3 - "$task_tmp/stats.json" <<'PY'
import json,sys
s=json.load(open(sys.argv[1]));assert not s['error'];assert any(r['name']=='fixture' for r in s['rows']);assert s['exit_health']['enabled'];assert s['exit_health']['outbounds'][0]['alive']
PY
  previous_xray=$(cat /opt/var/run/xray-fixture.pid)
  previous_auth=$(sha256sum /opt/etc/xkeen-stats/auth.json)
  "$task_tmp/installer" -install "${common[@]}" > "$task_tmp/reinstall.log" 2>&1
  test "$(cat /opt/var/run/xray-fixture.pid)" = "$previous_xray"
  test "$(sha256sum /opt/etc/xkeen-stats/auth.json)" = "$previous_auth"
  test ! -e /opt/etc/xkeen-stats/setup-token
  /opt/etc/init.d/S99xkeen-stats stop
  kill "$(cat /opt/var/run/xray-fixture.pid)" 2>/dev/null || true
  sleep 1
  rm -rf /opt/etc/xkeen-stats /opt/etc/xray /opt/var/lib/xkeen-stats
  rm -f /opt/sbin/xkeen-stats /opt/etc/init.d/S99xkeen-stats
  echo "Installer integration passed: $mode, custom LAN, first password, probes, idempotent reinstall"
done
