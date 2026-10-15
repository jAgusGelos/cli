#!/bin/bash
# Runner session entrypoint (uid 1000): Xvfb, NSS trust, managed policies, Chromium kiosk, then exec the agent.
set -euo pipefail

export HOME=/home/rbi DISPLAY=:99
RUN_DIR=/tmp/iwa
POLICY_DIR=$RUN_DIR/policies

fail() {
  printf '{"level":"error","event":"entrypoint_failed","error":"%s"}\n' "$1" >&2
  exit 1
}

[ "$(id -u)" = 1000 ] || fail "must run as uid 1000"
[[ "${IWA_DISPLAY:-}" =~ ^([0-9]{3,4})x([0-9]{3,4})@([0-9]{1,2})$ ]] || fail "invalid IWA_DISPLAY"
WIDTH=${BASH_REMATCH[1]}
HEIGHT=${BASH_REMATCH[2]}
[[ "${IWA_PROXY_ADDR:-}" =~ ^[0-9.]+:[0-9]{1,5}$ ]] || fail "invalid IWA_PROXY_ADDR"
[ -n "${IWA_START_URL:-}" ] || fail "missing IWA_START_URL"
[ -n "${IWA_CA_PEM:-}" ] || fail "missing IWA_CA_PEM"
case "$IWA_CA_PEM" in
  *"PRIVATE KEY"*) fail "IWA_CA_PEM contains a private key" ;;
  *"-----BEGIN CERTIFICATE-----"*) ;;
  *) fail "IWA_CA_PEM is not a PEM certificate" ;;
esac

umask 077
mkdir -p "$RUN_DIR" "$POLICY_DIR" "$HOME/.pki/nssdb"

Xvfb :99 -screen 0 "${WIDTH}x${HEIGHT}x24" -nolisten tcp >"$RUN_DIR/xvfb.log" 2>&1 &

certutil -d "sql:$HOME/.pki/nssdb" -N --empty-password
printf '%s\n' "$IWA_CA_PEM" >"$RUN_DIR/runner-ca.crt"
certutil -d "sql:$HOME/.pki/nssdb" -A -t "C,," -n iwa-runner-ca -i "$RUN_DIR/runner-ca.crt" \
  || fail "IWA_CA_PEM rejected by certutil"
rm -f "$RUN_DIR/runner-ca.crt"

cp /opt/iwa/policies/rbi.json "$POLICY_DIR/rbi.json"
python3 - "$POLICY_DIR/session.json" <<'PY' || fail "invalid IWA_ALLOWED_HOSTS"
import json, os, re, sys
hosts = json.loads(os.environ["IWA_ALLOWED_HOSTS"])
label = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
if not isinstance(hosts, list) or not hosts:
    sys.exit(1)
for h in hosts:
    if not isinstance(h, str) or len(h) > 253 or not re.fullmatch(rf"{label}(\.{label})*", h):
        sys.exit(1)
policy = {
    "URLAllowlist": ["https://" + h for h in hosts],
    "ProxySettings": {
        "ProxyMode": "fixed_servers",
        "ProxyServer": "http://" + os.environ["IWA_PROXY_ADDR"],
        "ProxyBypassList": "<-loopback>",
    },
}
with open(sys.argv[1], "w") as f:
    json.dump(policy, f, indent=2)
PY
chmod 0444 "$POLICY_DIR"/*.json
chmod 0555 "$POLICY_DIR"

for _ in $(seq 1 100); do
  xdpyinfo -display :99 >/dev/null 2>&1 && break
  sleep 0.1
done
xdpyinfo -display :99 >/dev/null 2>&1 || fail "Xvfb did not start"

chromium --kiosk --no-first-run --noerrdialogs --disable-session-crashed-bubble \
  --disable-background-networking --disable-component-update \
  --user-data-dir="$HOME/profile" --password-store=basic --window-position=0,0 \
  --window-size="${WIDTH},${HEIGHT}" \
  --load-extension=/opt/iwa/ext \
  --proxy-server="http://$IWA_PROXY_ADDR" --proxy-bypass-list="<-loopback>" \
  "$IWA_START_URL" >>"$RUN_DIR/chromium.log" 2>&1 &

exec python3 -m iwa_agent.main
