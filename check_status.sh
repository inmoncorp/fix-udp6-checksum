#!/bin/bash                                                                                                                                                                                          
if (( $# != 1 )); then
    echo "usage: $0 <interface>"
    exit 1;
fi
sudo tc -s filter show dev "$1" ingress

