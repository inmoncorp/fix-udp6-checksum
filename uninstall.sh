#!/bin/bash
if (( $# != 1 )); then
    echo "usage: $0 <interface>"
    exit 1;
fi
sudo tc filter del dev "$1" ingress protocol all pref 1 handle 0x1 bpf
sudo tc qdisc del dev "$1" clsact

