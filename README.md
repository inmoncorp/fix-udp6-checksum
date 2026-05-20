https://blog.sflow.com/2026/05/fixing-ghost-drops-how-ebpf-rescued.html

eBPF program to rewrite the UDP-over-IPv6 checksum.  For use only when you know the checksum is being computed wrong at the source.  This example is hardcoded for IPFIX only (4739/udp6).

To build, you will need a system running Docker:

% ./build.sh

The resulting .o file can be installed to a netdev on the target system like this:

% ./install.sh enp0s3

To confirm installation:

% ./check_status.sh enp0s3

To check that the kernel is not longer incrementing checksum errors:

% ./show_counters.sh

And to uninstall again:

% ./uninstall.sh enp0s3

If this workaround needs to persist across reboots then you will need to run the install command on reboot, e.g. using a systemctl unit file (not included here).

A  convenient command to log the IPv6 source addresses of packets that are now making it up the stack is:

% socat -b 0 -dd -u UDP6-RECV:4739 - 2>&1
