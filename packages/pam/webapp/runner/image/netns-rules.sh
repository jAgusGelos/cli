#!/bin/bash
# One-shot helper (root, NET_ADMIN only) that locks down the runner netns held by the pause container.
# Usage: netns-rules.sh <gatewayIp> <agentPort> <proxyPort>
set -euo pipefail

[ $# -eq 3 ] || { echo "usage: $0 <gatewayIp> <agentPort> <proxyPort>" >&2; exit 2; }
GW=$1 AGENT_PORT=$2 PROXY_PORT=$3
[[ "$GW" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { echo "invalid gateway ip" >&2; exit 2; }
for p in "$AGENT_PORT" "$PROXY_PORT"; do
  [[ "$p" =~ ^[0-9]{1,5}$ ]] && [ "$p" -ge 1 ] && [ "$p" -le 65535 ] || { echo "invalid port $p" >&2; exit 2; }
done

ipt() { iptables -w 5 "$@"; }

ipt -P INPUT DROP
ipt -P FORWARD DROP
ipt -P OUTPUT DROP
ipt -F INPUT
ipt -F FORWARD
ipt -F OUTPUT

ipt -A INPUT -i lo -j ACCEPT
ipt -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

ipt -A OUTPUT -o lo -d 127.0.0.1 -j ACCEPT
ipt -A OUTPUT -p tcp -d "$GW" --dport "$AGENT_PORT" -j ACCEPT
ipt -A OUTPUT -p tcp -d "$GW" --dport "$PROXY_PORT" -j ACCEPT
ipt -A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

iptables -S
