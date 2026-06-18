#!/bin/bash
if (( $# != 1 )); then
    echo "usage: $0 <interface>"
    exit 1;
fi
sudo tc qdisc add dev "$1" clsact
sudo tc filter add dev "$1" ingress pref 1 protocol ipv6 u32 \
     match ip6 protocol 17 0xff \
     match ip6 dport 4739 0xffff \
     action bpf obj fix_checksum.o sec tc/ingress

