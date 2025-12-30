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
   echo $(date +%s | md5sum | awk '{ print $1 }') > /etc/machine-id
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
echo "$(<./NetworkManager/10-ip6-privacy.conf)"
echo "$(<./NetworkManager/10-ip6-privacy.conf)" > "$NetworkManagerConf/10-ip6-privacy.conf"

echo "disable connectivity check in networkmanager"
echo "$(<./NetworkManager/11-connectivity-check-disable.conf)"
echo "$(<./NetworkManager/11-connectivity-check-disable.conf)" > "$NetworkManagerConf/11-connectivity-check-disable.conf"

echo "disable sending hostname in networkmanager"
echo "$(<./NetworkManager/12-dhcp-send-hostname-disable.conf)"
echo "$(<./NetworkManager/12-dhcp-send-hostname-disable.conf)" > "$NetworkManagerConf/12-dhcp-send-hostname-disable.conf"

echo "enable mac address randomization for scanning and connecting using networkmanager"
echo "$(<./NetworkManager/13-wifi-rand-mac.conf)"
echo "$(<./NetworkManager/13-wifi-rand-mac.conf)" > "$NetworkManagerConf/13-wifi-rand-mac.conf"

else
echo "skipping networkmanager config"
fi

echo "##### END NETWORKMANAGER SECTION #####"

echo "##### START SYSCTL SECTION #####"
# set sysctl conf dir
SysctlConf="/etc/sysctl.d"

read -r -p "apply kernel hardening? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "kernel hardening!"
echo "for details of what options look like check $SysctlConf/10-kernel-hardening.conf"
echo "$(<./sysctl/10-kernel-hardening.conf)"
echo "$(<./sysctl/10-kernel-hardening.conf)" > "$SysctlConf/10-kernel-hardening.conf"

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
echo " $(<./sysctl/20-network-hardening.conf)"
echo " $(<./sysctl/20-network-hardening.conf)" > "$SysctlConf/20-network-hardening.conf"

echo "check these options if you have breakage"
echo "the disabling of ipv6 router advertisements can cause issues if your network uses ipv6"
echo "the protect against smurf attacks can be turned off if you need to be able to ping this machine"
else
echo "skipping kernel network hardening"
fi

echo "##### END SYSCTL SECTION #####"

read -r -p "sandbox systemd services? [y/N] " response
if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]
then
echo "for details of what options look like check /etc/systemd/system/NetworkManager.service.d folder"
mkdir -p /etc/systemd/system/NetworkManager.service.d/
echo "$(<./systemd/NetworkManager.conf)"
echo "$(<./systemd/NetworkManager.conf)" > "/etc/systemd/system/NetworkManager.service.d/hardening.conf"

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
