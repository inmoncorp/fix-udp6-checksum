#!/bin/sh
sudo tc filter del dev "$1" ingress pref 1
sudo tc qdisc del dev "$1" clsact

