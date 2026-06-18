#!/bin/bash
if (( $# != 1 )); then
    echo "usage: $0 <interface>"
    exit 1;
fi
sudo tc filter del dev "$1" ingress protocol ipv6 pref 1 u32
sudo tc qdisc del dev "$1" clsact

