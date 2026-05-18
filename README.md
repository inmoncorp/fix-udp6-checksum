eBPF program to rewrite the UDP-over-IPv6 checksum.  For use only when you know the checksum is being computed wrong at the source.

To build, you will need a system running Docker:

% ./build.sh

The resulting .o file can be installed to a netdev on the target system like this:

% ./install.sh enp0s3

To confirm installation:

% ./check_status.sh

To check that the kernel is not longer incrementing checksum errors:

% ./show_counters.sh

And to uninstall again:

% ./uninstall.sh enp0s3

If this workaround needs to persist across reboots then you will need to run the install command on reboot, e.g. using a systemctl unit file (not included here).
