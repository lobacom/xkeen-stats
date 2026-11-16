#!/opt/bin/sh
# Загрузчик для Keenetic/Entware: архитектура ELF, HTTPS и подпись Ed25519.
set -eu
PATH=/opt/bin:/opt/sbin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

fail() { printf '%s\n' "$*" >&2; exit 1; }
usage() {
  cat <<'EOF'
XKeen Stats: установщик для Keenetic с Entware и работающим Xray.
  sh install.sh --check [параметры]   проверить без изменений
  sh install.sh [параметры]           установить
Параметры передаются программе:
  -interface br0 -listen 192.168.1.1:1001 -lan 192.168.1.0/24
  -config /opt/etc/xray/configs
  -xkeen-init /opt/etc/init.d/S05xkeen
  -source-config /path/to/generator-source.json
  -allow-xray-restart   разрешить перезапуск для включения статистики
Адреса и пути выше — примеры, обычно они определяются автоматически.
Пароль создаётся в браузере по одноразовой ссылке после установки.
EOF
}
case "${1:-}" in --help|-h) usage; exit 0;; esac
test "$(id -u)" = 0 || fail 'Запустите установщик от root в shell Entware.'
test -f /opt/etc/init.d/rc.func || fail 'Сначала установите Entware и XKeen с Xray.'
for tool in curl openssl od dd awk sha256sum base64 mktemp; do
  command -v "$tool" >/dev/null 2>&1 || fail "Не найдена утилита $tool. Нужны curl, ca-bundle, openssl-util и базовые утилиты Entware."
done

# uname не различает endianness MIPS и разрядность пользовательского окружения.
elf=/opt/bin/busybox
test -f "$elf" || elf=/bin/busybox
test -f "$elf" || fail 'Не найден ELF busybox для определения архитектуры.'
# Урезанный BusyBox od не поддерживает -A/-t/-j/-N; dd и od -b есть и в нём.
machine=$(dd if="$elf" bs=1 skip=18 count=2 2>/dev/null | od -b | awk 'NR==1 {print $2, $3}')
class=$(dd if="$elf" bs=1 skip=4 count=1 2>/dev/null | od -b | awk 'NR==1 {print $2}')
case "$class:$machine" in
  '002:076 000') arch=amd64;;
  '002:267 000') arch=arm64;;
  '001:050 000') case "$(uname -m)" in armv7*|armv8*) arch=armv7;; *) fail 'Требуется ARMv7 или новее.';; esac;;
  '001:010 000') arch=mipsle;;
  '001:000 010') arch=mips;;
  *) fail "Нет сборки для ELF $class/$machine. Доступны amd64, arm64, armv7, mips и mipsle.";;
esac

mkdir -p /opt/tmp
tmp=$(mktemp -d /opt/tmp/xkeen-stats-install.XXXXXX)
cleanup() { case "$tmp" in /opt/tmp/xkeen-stats-install.*) rm -rf -- "$tmp";; esac; }
trap cleanup EXIT
trap 'exit 1' HUP INT TERM
fetch() { curl --fail --silent --show-error --location --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 "$1" -o "$2"; }
base=https://github.com/lobacom/xkeen-stats/releases
fetch "$base/latest/download/SHA256SUMS" "$tmp/SHA256SUMS"
tag=$(sed -n '1s/^# xkeen-stats //p' "$tmp/SHA256SUMS")
printf '%s\n' "$tag" | grep -Eq '^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$' || fail 'Некорректная версия в манифесте.'
fetch "$base/download/$tag/SHA256SUMS.sig" "$tmp/signature.txt"
tr -d '\r\n' < "$tmp/signature.txt" | base64 -d > "$tmp/signature"
cat > "$tmp/key.pem" <<'EOF'
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAMeXlQXEJ/oazafi9vpo3hdUhxmpKB8fIHsSv6oGNCRM=
-----END PUBLIC KEY-----
EOF
openssl pkeyutl -verify -pubin -inkey "$tmp/key.pem" -rawin -in "$tmp/SHA256SUMS" -sigfile "$tmp/signature" >/dev/null 2>&1 || fail 'Подпись релиза не прошла проверку. Нужен OpenSSL с поддержкой pkeyutl -rawin и Ed25519.'
asset=xkeen-stats-linux-$arch
expected=$(awk -v name="$asset" '$2 == name {print $1; n++} END {if(n != 1) exit 1}' "$tmp/SHA256SUMS") || fail 'Сборка отсутствует или повторяется в манифесте.'
printf '%s\n' "$expected" | grep -Eq '^[0-9a-f]{64}$' || fail 'Некорректная контрольная сумма.'
printf 'Загружаю %s (%s)…\n' "$tag" "$arch"
fetch "$base/download/$tag/$asset" "$tmp/installer"
actual=$(sha256sum "$tmp/installer" | cut -d ' ' -f 1)
test "$actual" = "$expected" || fail 'Контрольная сумма бинарника не совпала.'
chmod 700 "$tmp/installer"
test "$("$tmp/installer" -version)" = "$tag" || fail 'Версия бинарника не совпала с подписанным релизом.'
action=-install
if test "${1:-}" = --check; then action=-install-plan; shift; fi
"$tmp/installer" "$action" "$@"
