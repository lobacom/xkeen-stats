#!/opt/bin/sh
# Статистика разрешена только основной LAN при настроенном собственном пароле.
set -eu
PATH=/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
chain=XKSTATS_LAN
iptables -nL "$chain" >/dev/null 2>&1 || iptables -N "$chain"
iptables -C "$chain" -i lo -j ACCEPT >/dev/null 2>&1 || iptables -I "$chain" 1 -i lo -j ACCEPT
if /opt/sbin/xkeen-stats -check-auth >/dev/null 2>&1; then
  iptables -C "$chain" -i br0 -s 192.168.1.0/24 -d 192.168.1.1 -j ACCEPT >/dev/null 2>&1 || iptables -I "$chain" 2 -i br0 -s 192.168.1.0/24 -d 192.168.1.1 -j ACCEPT
else
  if iptables -C "$chain" -i br0 -s 192.168.1.0/24 -d 192.168.1.1 -j ACCEPT >/dev/null 2>&1; then
    iptables -D "$chain" -i br0 -s 192.168.1.0/24 -d 192.168.1.1 -j ACCEPT
  fi
fi
iptables -C "$chain" -p tcp -j REJECT --reject-with tcp-reset >/dev/null 2>&1 || iptables -A "$chain" -p tcp -j REJECT --reject-with tcp-reset
iptables -C INPUT -p tcp --dport 1001 -j "$chain" >/dev/null 2>&1 || iptables -I INPUT 1 -p tcp --dport 1001 -j "$chain"
