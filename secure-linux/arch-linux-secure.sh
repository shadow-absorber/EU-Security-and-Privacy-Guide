#!/usr/bin/env bash

# Function to display usage information
function show_help() {
    echo "Usage: ${0##*/} [OPTIONS]"
    echo "A script to make arch linux more secure and privacy respecting"
    echo
    echo "Options:"
    echo "  -h, --help        Show this help message and exit."
    echo "  -r, --revert      revert changes from running script normally"
    echo "no options:         run hardening script"
    echo
    echo "Ensure you run this script as root."
}

function revert() {
   if [ "$EUID" -ne 0 ]; then
    echo "MUST RUN AS ROOT"
    exit 1
   fi
   echo "removing networkmanager config"
   rm /etc/NetworkManager/conf.d/10-ip6-privacy.conf
   rm /etc/NetworkManager/conf.d/11-connectivity-check-disable.conf
   rm /etc/NetworkManager/conf.d/12-dhcp-send-hostname-disable.conf
   rm /etc/NetworkManager/conf.d/13-wifi-rand-mac.conf
   echo
   echo "removing sysctl config"
   rm /etc/sysctl.d/10-kernel-hardening.conf
   rm /etc/sysctl.d/20-network-hardening.conf
   echo
   echo "remove systemd service sandboxing"
   rm /etc/systemd/system/NetworkManager.service.d/hardening.conf
   echo
   echo "setting machine id to random number"
   echo $(date +%s | md5sum | awk '{ print $1 }')
   echo
   echo "set your machine hostname with:"
   echo "hostnamectl hostname whatYouWantToCallYourComputer"
   echo
   echo "set your time zone with:"
   echo "timedatectl set-timezone continent/city"
   echo "for list of timezones run:"
   echo "timedatectl list-timezones"
   echo
   echo "reflash bios to get old secure boot keys back"
   echo "or disable secure boot"
   echo
   echo "to finalize the changes reboot"
}
# Check for help option
while [[ "$#" -gt 0 ]]; do
	case "$1" in
		-h|--help) show_help; exit 0 ;;
		-r|--revert) revert; exit 0 ;;
		*) echo "Unknown option: $1"; show_help; exit 1 ;;
	esac
		shift
done

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
echo "check these settings if you have breakage"
echo "disable namespaces as it can break systemd services running in --user mode"
echo "vm.swappiness as it can make your machine worse of or starved of ram"
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
echo "check these options if you have breakage"
echo "the disabling of ipv6 router advertisements can cause issues if your network uses ipv6"
echo "the protect against smurf attacks can be turned off if you need to be able to ping this machine"
else
echo "skipping kernel network hardening"
fi

echo "##### EN SYSCTL SECTION #####"

read -r -p "sandbox systemd services? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "for details of what options look like check /etc/systemd/system/NetworkManager.service.d folder"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
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

echo "WARNING this can't be undone!!!"
read -r -p "enable secure boot? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "remove old secure boot keys"
echo "enter secure boto setup mode"
echo "check online for how to do this for your laptop"
echo "or for your motherboard"
echo "use the following command to reboot into bios/uefi"
echo "systemctl reboot --firmware-setup"
echo "run the following commands as root"
echo "sbctl status"
echo "sbctl create-keys"
echo "sbctl enroll-keys -m"
echo "sbctl verify"
echo "sbctl verify | sed -E 's|^.* (/.+) is not signed$|sbctl sign -s \"\1\"|e'"
echo "sbctl sign -s -o /usr/lib/systemd/boot/efi/systemd-bootx64.efi.signed /usr/lib/systemd/boot/efi/systemd-bootx64.efi"
echo 
echo "now reboot and enable secure boot in bios/uefi"
else
echo "skipping explaining secure boot"
fi
echo
echo "to finalize the changes reboot"
