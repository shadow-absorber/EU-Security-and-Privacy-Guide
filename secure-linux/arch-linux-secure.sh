#!/usr/bin/env bash

if [ "$EUID" -ne 0 ]
then
echo "MUST RUN AS ROOT"
exit
fi

echo "####### START NETWORKMANAGER SECTION #####"
# sets networkmanager conf dir
NetworkManagerConf="/etc/NetworkManager/conf.d/"    

read -r -p "apply networkmanager config? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then  
echo "enable privacy extensions for ipv6 in networkmanager"
cat > "$NetworkManagerConf/10-ip6-privacy.conf" << 'EOF'
# enable privacy extension for ipv6
[connection]
ipv6.ip6-privacy=2
EOF

echo "disable connectivity check in networkmanager"
cat > "$NetworkManagerConf/11-connectivity-check-disable.conf" << 'EOF'
# disable connectivity check
[connectivity]
enabled=false
EOF

echo "disable sending hostname in networkmanager"
cat > "$NetworkManagerConf/12-dhcp-send-hostname-disable.conf" << 'EOF'
# disable sending hostname
[connection]
ipv4.dhcp-send-hostname=0
ipv6.dhcp-send-hostname=0
EOF

echo "enable mac address randomization for scanning and connecting using networkmanager"
cat > "$NetworkManagerConf/13-wifi-rand-mac.conf" << 'EOF'
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

echo "##### EOF NETWORKMANAGER SECTION #####"

echo "##### START SYSCTL SECTION #####"
# set sysctl conf dir
SysctlConf="/etc/sysctl.d"

read -r -p "apply kernel hardening? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "kernel hardening!"
echo "for details of what options look like check $SysctlConf/10-kernel-hardening.conf"
cat > "$SysctlConf/10-kernel-hardening.conf"  << 'EOF'
# mitigate kernel pointer leaks
kernel.kptr_restrict=2

# restrict dmesg to CAP_SYSLOG
kernel.dmesg_restrict=1

# restrict eBPF to CAP_BPF and enable JIT hardening
kernel.unprivileged_bpf_disabled=1
net.core.bpf_jit_harden=2

# restrict TTY line disciplines to CAP_SYS_MODULE
dev.tty.ldisc_autoload=0

# restrict userfaultfd to CAP_SYS_PTRACE as it can be used for use_after_free exploits
vm.unprivileged_userfaultfd=0

# disable loading a new kernel while running
kernel.kexec_load_disabled=1

# disable sysrq as it can be used remotely
kernel.sysrq=0

# disable namespaces for none CAP_SYS_ADMIN
# this is disabled as it breaks mpd
#kernel.unprivileged_userns_clone=0

# restricts perf events to CAP_PERFMON
kernel.perf_event_paranoid=3

# only use swap if needed as it can leak sensitive data
vm.swappiness=1
EOF
else
echo "skipping kernel hardening"
fi

read -r -p "apply network kernel hardening? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "networking hardening!"

echo "for details of what options look like check $SysctlConf/20-network-hardening.conf"
cat > "$SysctlConf/20-network-hardening.conf" << 'EOF'
# protect against syn flood attacks
net.ipv4.tcp_syncookies=1

# drop RST packets for sockets in time-wait state
net.ipv4.tcp_rfc1337=1

# protect against IP spoofing
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1

# disable icmp redirects to prevent man-in-the-middle
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0

# protect against smurf attacks
net.ipv4.icmp_echo_ignore_all=1

# disable source routing to prevent man-in-the-middle
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0

# disable ipv6 router advertisements
net.ipv6.conf.all.accept_ra=0
net.ipv6.conf.default.accept_ra=0

# disable tcp sack as it has been used commonly for exploits
net.ipv4.tcp_sack=0
net.ipv4.tcp_dsack=0
net.ipv4.tcp_fack=0

# disable tcp timestamps
net.ipv4.tcp_timestamps=0

# enable ipv6 privacy extensions on kernel level
net.ipv6.conf.all.use_tempaddr=2
net.ipv6.conf.default.use_tempaddr=2
EOF
else
echo "skipping kernel network hardening"
fi

echo "##### EN SYSCTL SECTION #####"

read -r -p "sandbox systemd services? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "for details of what options look like check /etc/systemd/system/NetworkManager.service.d folder"
cat > "/etc/systemd/system/NetworkManager.service.d/hardening.conf" << 'EOF'
[Service]
##############
# Networking #
##############

# PrivateNetwork= service needs access to host network
RestrictAddressFamilies=AF_INET AF_INET6 AF_NETLINK AF_PACKET AF_UNIX
# IPAccounting=yes
# IPAddressAllow=any
# IPAddressDeny= service needs access to all IPs

###############
# File system #
###############
#  Note that the effect of these settings may be undone by privileged processes. In order to
#  set up an effective sandboxed environment for a unit it is thus recommended to combine
#  these settings with either CapabilityBoundingSet=~CAP_SYS_ADMIN or
#  SystemCallFilter=~@mount.

ProtectHome=yes
ProtectSystem=strict
ProtectProc=invisible
ReadWritePaths=/etc -/proc/sys/net -/var/lib/NetworkManager/
PrivateTmp=yes

###################
# User separation #
###################

# PrivateUsers= service runs as root
# DynamicUser= service runs as root

###########
# Devices #
###########

PrivateDevices=yes
# DeviceAllow=/dev/exampledevice

##########
# Kernel #
##########

ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes

########
# Misc #
########

CapabilityBoundingSet=~CAP_SYS_ADMIN CAP_SETUID CAP_SETGID CAP_SYS_CHROOT
# AmbientCapabilities= service runs as root
NoNewPrivileges=yes
ProtectHostname=yes
ProtectClock=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes
RestrictSUIDSGID=yes
# RemoveIPC= service runs as root

################
# System calls #
################

SystemCallFilter=@system-service @privileged
# SystemCallFilter= service needs all calls in @system-service
SystemCallArchitectures=native
EOF
else
echo "skipping systemd service sandboxing"
fi

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
