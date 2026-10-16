#!/bin/sh
# Reviewed production integration helper. Never run during an isolated pilot.
# This is independent of OpenClash's firewall removal and DNS restore paths.
set -eu
G=${DNS_GENERATION:?}
nft -c -f "$G/config/dns-integrity.nft"
nft -f "$G/config/dns-integrity.nft"
uci -q delete 'dhcp.@dnsmasq[0].server' || true
uci set 'dhcp.@dnsmasq[0].noresolv=1'
uci add_list 'dhcp.@dnsmasq[0].server=127.0.0.1#6053'
uci set 'openclash.config.dnsmasq_noresolv=1'
uci -q delete 'openclash.config.dnsmasq_server' || true
uci add_list 'openclash.config.dnsmasq_server=127.0.0.1#6053'
uci commit dhcp
uci commit openclash
/etc/init.d/dnsmasq reload
