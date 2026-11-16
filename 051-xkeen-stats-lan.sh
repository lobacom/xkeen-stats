#!/opt/bin/sh
# Адрес, подсеть и LAN-интерфейс берутся из закрытого service.json.
set -eu
PATH=/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
exec /opt/sbin/xkeen-stats -firewall
