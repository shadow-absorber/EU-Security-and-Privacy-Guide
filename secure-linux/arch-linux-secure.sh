#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
then
    echo "MUST RUN AS ROOT"
    exit
fi

echo "####### START NETWORKMANAGER SECTION #####"

read -r -p "apply networkmanager config? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then  
    # sets networkmanager conf dir
    NetworkManagerConf="/etc/NetworkManager/conf.d/"
    
    echo "enable privacy extensions for ipv6 in networkmanager"
    cat >> "$NetworkManagerConf/10-ip6-privacy.conf" << 'EOF'
    # enable privacy extension for ipv6
    [connection]
    ipv6.ip6-privacy=2
    EOF

    echo "disable connectivity check in networkmanager"
    cat >> "$NetworkManagerConf/11-connectivity-check-disable.conf" << 'EOF'
    # disable connectivity check
    [connectivity]
    enabled=false
    EOF

    echo "disable sending hostname in networkmanager"
    cat >> "$NetworkManagerConf/12-dhcp-send-hostname-disable.conf" << 'EOF'
    # disable sending hostname
    [connection]
    ipv4.dhcp-send-hostname=0
    ipv6.dhcp-send-hostname=0
    EOF

    echo "enable mac address randomization for scanning and connecting using networkmanager"
    cat >> "$NetworkManagerConf/13-wifi-rand-mac.conf" << 'EOF'
    # enable mac address randomization
    #
    # yes is already the default for scanning
    [device-mac-randomization]
    wifi.scan-rand-mac-address=yes
    [connection-mac-randomization]
    # Randomize MAC for every ethernet connection
    ethernet.cloned-mac-address=random
    # Generate a random MAC for each Wi-Fi and associate the two permanently.
    wifi.cloned-mac-address=stable
    EOF
else
    echo "skipping networkmanager config"
fi

echo "##### END NETWORKMANAGER SECTION #####"

echo "##### START SYSCTL SECTION #####"

read -r -p "apply kernel hardening? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "kernel hardening!"
    echo "# mitigate kernel pointer leaks"
    echo "kernel.kptr_restrict=2" > /etc/sysctl.d/10-kernel-hardening.conf
    echo "# restrict dmesg to CAP_SYSLOG"
    echo "kernel.dmesg_restrict=1" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# restrict eBPF to CAP_BPF and enable JIT hardening"
    echo "kernel.unprivileged_bpf_disabled=1" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "net.core.bpf_jit_harden=2" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# restrict TTY line disciplines to CAP_SYS_MODULE"
    echo "dev.tty.ldisc_autoload=0" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# restrict userfaultfd to CAP_SYS_PTRACE as it can be used for use_after_free exploits"
    echo "vm.unprivileged_userfaultfd=0" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# disable loading a new kernel while running"
    echo "kernel.kexec_load_disabled=1" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# disable sysrq as it can be used remotely"
    echo "kernel.sysrq=0" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# disable namespaces for none CAP_SYS_ADMIN"
    echo "kernel.unprivileged_userns_clone=0" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# restricts perf events to CAP_PERFMON"
    echo "kernel.perf_event_paranoid=3" >> /etc/sysctl.d/10-kernel-hardening.conf
    echo "# only use swap if needed as it can leak sensitive data"
    echo "vm.swappiness=1" >> /etc/sysctl.d/10-kernel-hardening.conf
else
    echo "skipping kernel hardening"
fi

read -r -p "apply network kernel hardening? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "networking hardening!"
    echo "# protect against syn flood attacks"
    echo "net.ipv4.tcp_syncookies=1" > /etc/sysctl.d/20-network-hardening.conf
    echo "# drop RST packets for sockets in time-wait state"
    echo "net.ipv4.tcp_rfc1337=1" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# protect against IP spoofing"
    echo "net.ipv4.conf.all.rp_filter=1" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.default.rp_filter=1" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# disable icmp redirects to prevent man-in-the-middle"
    echo "net.ipv4.conf.all.accept_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.default.accept_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.all.secure_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.default.secure_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv6.conf.all.accept_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv6.conf.default.accept_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.all.send_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.default.send_redirects=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# protect against smurf attacks"
    echo "net.ipv4.icmp_echo_ignore_all=1" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# disable source routing to prevent man-in-the-middle"
    echo "net.ipv4.conf.all.accept_source_route=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.conf.default.accept_source_route=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv6.conf.all.accept_source_route=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv6.conf.default.accept_source_route=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# disable ipv6 router advertisements"
    echo "net.ipv6.conf.all.accept_ra=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv6.conf.default.accept_ra=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# disable tcp sack as it has been used commonly for exploits"
    echo "net.ipv4.tcp_sack=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.tcp_dsack=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv4.tcp_fack=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# disable tcp timestamps"
    echo "net.ipv4.tcp_timestamps=0" >> /etc/sysctl.d/20-network-hardening.conf
    echo "# enable ipv6 privacy extensions on kernel level"
    echo "net.ipv6.conf.all.use_tempaddr=2" >> /etc/sysctl.d/20-network-hardening.conf
    echo "net.ipv6.conf.default.use_tempaddr=2" >> /etc/sysctl.d/20-network-hardening.conf
else
    echo "skipping kernel network hardening"
fi

echo "##### EN SYSCTL SECTION #####"

read -r -p "change machine id? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "change machine id number to whonix id number"
    echo "b08dfa6083e7567a1921a715000001fb" > /etc/machine-id
else
    echo "skipping machine id change"
fi

read -r -p "change hostname to generic one? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "change hostname of computer to generic one"
    hostnamectl hostname arch
else
    echo "skipping hostname change"
fi

read -r -p "change timezone to UTC? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
    echo "setting timezone to UTC"
    timedatectl set-timezone UTC
else
    echo "skipping changing timezone"
fi

