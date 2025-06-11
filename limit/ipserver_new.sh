#!/bin/bash
interface=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

# Flush existing rules
nft flush ruleset

# Create tables and chains
nft add table inet filter
nft add chain inet filter INPUT { type filter hook input priority 0 \; policy accept \; }
nft add chain inet filter FORWARD { type filter hook forward priority 0 \; policy accept \; }
nft add chain inet filter OUTPUT { type filter hook output priority 0 \; policy accept \; }
nft add table ip nat
nft add chain ip nat PREROUTING { type nat hook prerouting priority 0 \; policy accept \; }
nft add chain ip nat POSTROUTING { type nat hook postrouting priority 0 \; policy accept \; }

# Add input rules
nft add rule inet filter INPUT tcp dport 10015 accept
nft add rule inet filter INPUT tcp dport 10012 accept
nft add rule inet filter INPUT tcp dport 10011 accept
nft add rule inet filter INPUT tcp dport 10008 accept
nft add rule inet filter INPUT tcp dport 10007 accept
nft add rule inet filter INPUT tcp dport 10006 accept
nft add rule inet filter INPUT tcp dport 10005 accept
nft add rule inet filter INPUT tcp dport 10004 accept
nft add rule inet filter INPUT tcp dport 10003 accept
nft add rule inet filter INPUT tcp dport 10002 accept
nft add rule inet filter INPUT tcp dport 10001 accept
nft add rule inet filter INPUT tcp dport 10000 accept
nft add rule inet filter INPUT tcp dport 8080 accept
nft add rule inet filter INPUT tcp dport 3128 accept
nft add rule inet filter INPUT tcp dport 1194 accept
nft add rule inet filter INPUT tcp dport 443 accept
nft add rule inet filter INPUT tcp dport 109 accept
nft add rule inet filter INPUT tcp dport 169 accept
nft add rule inet filter INPUT tcp dport 88 accept
nft add rule inet filter INPUT tcp dport 80 accept
nft add rule inet filter INPUT tcp dport 68 accept
nft add rule inet filter INPUT udp dport 53 accept
nft add rule inet filter INPUT udp dport 2200 accept
nft add rule inet filter INPUT udp dport 2100 accept
nft add rule inet filter INPUT udp dport 5300 accept
nft add rule inet filter INPUT udp dport 7100 accept
nft add rule inet filter INPUT udp dport 7200 accept
nft add rule inet filter INPUT udp dport 7300 accept

# Add forward rules (BitTorrent blocking)
nft add rule inet filter FORWARD string "BitTorrent" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "BitTorrent protocol" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "peer_id=" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string ".torrent" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "announce.php?passkey=" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "torrent" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "announce" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "info_hash" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "/default.ida?" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string ".exe?/c+dir" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string ".exe?/c_tftp" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "peer_id" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "BitTorrent" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "BitTorrent protocol" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "bittorrent-announce" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "announce.php?passkey=" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "find_node" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "info_hash" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "get_peers" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "announce" limit rate 100kbytes/second queue num 1 drop
nft add rule inet filter FORWARD string "announce_peers" limit rate 100kbytes/second queue num 1 drop

# Add NAT rules
nft add rule ip nat PREROUTING iifname "$interface" udp dport 53 redirect to :5300
nft add rule ip nat POSTROUTING oifname "$interface" saddr 10.8.0.0/24 masquerade
nft add rule ip nat POSTROUTING oifname "$interface" saddr 20.8.0.0/24 masquerade

# IPv6 - Accepting all traffic
nft add table ip6 filter
nft add chain ip6 filter INPUT { type filter hook input priority 0 \; policy accept \; }
nft add chain ip6 filter FORWARD { type filter hook forward priority 0 \; policy accept \; }
nft add chain ip6 filter OUTPUT { type filter hook output priority 0 \; policy accept \; }

# Save the ruleset
nft list ruleset > /etc/nftables.conf
systemctl enable nftables.service
systemctl restart nftables.service
