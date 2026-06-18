#!/bin/sh
sudo tc qdisc add dev "$1" clsact
sudo tc filter add dev "$1" ingress pref 1 bpf da obj fix_checksum.o sec tc/ingress

