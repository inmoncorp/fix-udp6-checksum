#!/bin/sh
sudo tc -s filter show dev "$1" ingress

