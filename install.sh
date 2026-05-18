#!/bin/sh
sudo tc qdisc add dev "$1" clsact
sudo tc filter add dev "$1" ingress bpf da obj fix_checksum.o sec tc/ingress

