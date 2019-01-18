#!/bin/bash
## This script is to automate the preparation for a debian file system, which will be used for
## an ONIE installer image.
##
## USAGE:
##   USERNAME=username PASSWORD=password ./build_debian
## ENVIRONMENT:
##   USERNAME
##          The name of the default admin user
##   PASSWORD
##          The password, expected by chpasswd command

## Default user
[ -n "$USERNAME" ] || {
    echo "Error: no or empty USERNAME"
    exit 1
}

## Password for the default user
[ -n "$PASSWORD" ] || {
    echo "Error: no or empty PASSWORD"
    exit 1
}

## Include common functions
. functions.sh

## Enable debug output for script
set -x -e

## docker engine version (with platform)
LINUX_KERNEL_VERSION=4.4.0

## Working directory to prepare the file system
FILESYSTEM_ROOT=./fsroot
PLATFORM_DIR=platform
## Hostname for the linux image
HOSTNAME=sonic
DEFAULT_USERINFO="Default admin user,,,"

## Read ONIE image related config file
. ./onie-image.conf

[ -n "$ONIE_INSTALLER_PAYLOAD" ] || {
    echo "Error: Invalid ONIE_INSTALLER_PAYLOAD in onie image config file"
    exit 1
}
[ -n "$FILESYSTEM_SQUASHFS" ] || {
    echo "Error: Invalid FILESYSTEM_SQUASHFS in onie image config file"
    exit 1
}

## Prepare the file system directory
if [[ -d $FILESYSTEM_ROOT ]]; then
    sudo rm -rf $FILESYSTEM_ROOT || die "Failed to clean chroot directory"
fi
mkdir -p $FILESYSTEM_ROOT
mkdir -p $FILESYSTEM_ROOT/$PLATFORM_DIR
mkdir -p $FILESYSTEM_ROOT/$PLATFORM_DIR/x86_64-grub
touch $FILESYSTEM_ROOT/$PLATFORM_DIR/firsttime

## Build a basic Debian system by debootstrap
echo '[INFO] Debootstrap...'
sudo LANG=C debootstrap --variant=minbase --arch amd64 stretch $FILESYSTEM_ROOT file:///home/zhanggl/develop/git/build-debian/target

## Config hostname and hosts, otherwise 'sudo ...' will complain 'sudo: unable to resolve host ...'
sudo LANG=C chroot $FILESYSTEM_ROOT /bin/bash -c "echo '$HOSTNAME' > /etc/hostname"
sudo LANG=C chroot $FILESYSTEM_ROOT /bin/bash -c "echo '127.0.0.1       $HOSTNAME' >> /etc/hosts"
sudo LANG=C chroot $FILESYSTEM_ROOT /bin/bash -c "echo '127.0.0.1       localhost' >> /etc/hosts"

## Config basic fstab
sudo LANG=C chroot $FILESYSTEM_ROOT /bin/bash -c 'echo "proc /proc proc defaults 0 0" >> /etc/fstab'
sudo LANG=C chroot $FILESYSTEM_ROOT /bin/bash -c 'echo "sysfs /sys sysfs defaults 0 0" >> /etc/fstab'

## Note: mounting is necessary to makedev and install linux image
echo '[INFO] Mount all'
## Output all the mounted device for troubleshooting
mount
trap_push 'sudo umount $FILESYSTEM_ROOT/proc || true'
sudo LANG=C chroot $FILESYSTEM_ROOT mount proc /proc -t proc

## Pointing apt to public apt mirrors and getting latest packages, needed for latest security updates
sudo cp files/apt/sources.list $FILESYSTEM_ROOT/etc/apt/
##sudo cp files/apt/apt.conf.d/{81norecommends,apt-{clean,gzip-indexes,no-languages}} $FILESYSTEM_ROOT/etc/apt/apt.conf.d/
##sudo LANG=C chroot $FILESYSTEM_ROOT bash -c 'apt-mark auto `apt-mark showmanual`'

## Note: set lang to prevent locale warnings in your chroot
##sudo LANG=C chroot $FILESYSTEM_ROOT apt-get -y update
##sudo LANG=C chroot $FILESYSTEM_ROOT apt-get -y upgrade
echo '[INFO] Install packages for building image'
sudo LANG=C chroot $FILESYSTEM_ROOT apt-get -y install makedev psmisc systemd-sysv

## Create device files
echo '[INFO] MAKEDEV'
sudo LANG=C chroot $FILESYSTEM_ROOT /bin/bash -c 'cd /dev && MAKEDEV generic'
## Install initramfs-tools and linux kernel
## Note: initramfs-tools recommends depending on busybox, and we really want busybox for
## 1. commands such as touch
## 2. mount supports squashfs
## However, 'dpkg -i' plus 'apt-get install -f' will ignore the recommended dependency. So
## we install busybox explicitly
##sudo LANG=C chroot $FILESYSTEM_ROOT apt-get -y install busybox
echo '[INFO] Install linux kernel image'
## Note: duplicate apt-get command to ensure every line return zero
sudo dpkg --root=$FILESYSTEM_ROOT -i target/debs/initramfs-tools-core_*.deb || \
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -f
sudo dpkg --root=$FILESYSTEM_ROOT -i target/debs/initramfs-tools_*.deb || \
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -f
sudo dpkg --root=$FILESYSTEM_ROOT -i target/debs/linux-image-${LINUX_KERNEL_VERSION}-amd64_*.deb || \
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -f
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install acl


## Create default user
## Note: user should be in the group with the same name, and also in sudo/docker group
sudo LANG=C chroot $FILESYSTEM_ROOT useradd -G sudo $USERNAME -c "$DEFAULT_USERINFO" -m -s /bin/bash
## Create password for the default user
echo "$USERNAME:$PASSWORD" | sudo LANG=C chroot $FILESYSTEM_ROOT chpasswd

## Pre-install hardware drivers
sudo LANG=C chroot $FILESYSTEM_ROOT apt-get -y install      \
    firmware-linux-nonfree

## Pre-install the fundamental packages
## Note: gdisk is needed for sgdisk in install.sh
## Note: parted is needed for partprobe in install.sh
## Note: ca-certificates is needed for easy_install
## Note: don't install python-apt by pip, older than Debian repo one
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install      \
    file                    \
    ifupdown                \
    iproute2                \
    bridge-utils            \
    isc-dhcp-client         \
    sudo                    \
    vim                     \
    tcpdump                 \
    dbus                    \
    ntp                     \
    ntpstat                 \
    openssh-server          \
    python                  \
    python-setuptools       \
    monit                   \
    python-apt              \
    traceroute              \
    iputils-ping            \
    net-tools               \
    bsdmainutils            \
    ca-certificates         \
    i2c-tools               \
    efibootmgr              \
    usbutils                \
    pciutils                \
    iptables-persistent     \
    logrotate               \
    curl                    \
    kexec-tools             \
    less                    \
    unzip                   \
    gdisk                   \
    sysfsutils              \
    grub2-common            \
    rsyslog                 \
    ethtool                 \
    screen                  \
    hping3                  \
    python-scapy            \
    tcptraceroute           \
    mtr-tiny                \
    locales

#Adds a locale to a debian system in non-interactive mode
sudo sed -i '/^#.* en_US.* /s/^#//' $FILESYSTEM_ROOT/etc/locale.gen && \
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT locale-gen "en_US.UTF-8"
sudo LANG=en_US.UTF-8 DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT update-locale "LANG=en_US.UTF-8"
sudo LANG=C chroot $FILESYSTEM_ROOT bash -c "find /usr/share/i18n/locales/ ! -name 'en_US' -type f -exec rm -f {} +"

# Install certain fundamental packages from stretch-backports in order to get
# more up-to-date (but potentially less stable) versions
sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y -t stretch-backports install \
    picocom

sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y download \
    grub-pc-bin

sudo mv $FILESYSTEM_ROOT/grub-pc-bin*.deb $FILESYSTEM_ROOT/$PLATFORM_DIR/x86_64-grub

sudo dpkg --root=$FILESYSTEM_ROOT -i target/debs/libwrap0_*.deb || \
    sudo LANG=C DEBIAN_FRONTEND=noninteractive chroot $FILESYSTEM_ROOT apt-get -y install -f

## Disable kexec supported reboot which was installed by default
sudo sed -i 's/LOAD_KEXEC=true/LOAD_KEXEC=false/' $FILESYSTEM_ROOT/etc/default/kexec

## Fix ping tools permission so non root user can directly use them
## Note: this is a workaround since aufs doesn't support extended attributes
## Ref: https://github.com/moby/moby/issues/5650#issuecomment-303499489
## TODO: remove workaround when the overlay filesystem support extended attributes
sudo chmod u+s $FILESYSTEM_ROOT/bin/ping{,6}

## Remove sshd host keys, and will regenerate on first sshd start
sudo rm -f $FILESYSTEM_ROOT/etc/ssh/ssh_host_*_key*
sudo cp files/sshd/host-ssh-keygen.sh $FILESYSTEM_ROOT/usr/local/bin/
sudo cp -f files/sshd/sshd.service $FILESYSTEM_ROOT/lib/systemd/system/ssh.service
## Config sshd
sudo augtool --autosave "set /files/etc/ssh/sshd_config/UseDNS no" -r $FILESYSTEM_ROOT
sudo sed -i 's/^ListenAddress ::/#ListenAddress ::/' $FILESYSTEM_ROOT/etc/ssh/sshd_config
sudo sed -i 's/^#ListenAddress 0.0.0.0/ListenAddress 0.0.0.0/' $FILESYSTEM_ROOT/etc/ssh/sshd_config



## Config DHCP for eth0
sudo tee -a $FILESYSTEM_ROOT/etc/network/interfaces > /dev/null <<EOF

auto eth0
allow-hotplug eth0
iface eth0 inet dhcp
EOF


## Update initramfs
sudo chroot $FILESYSTEM_ROOT update-initramfs -u

## Clean up apt
sudo LANG=C chroot $FILESYSTEM_ROOT apt-get autoremove
sudo LANG=C chroot $FILESYSTEM_ROOT apt-get autoclean
sudo LANG=C chroot $FILESYSTEM_ROOT apt-get clean
sudo LANG=C chroot $FILESYSTEM_ROOT bash -c 'rm -rf /usr/share/doc/* /usr/share/locale/* /var/lib/apt/lists/* /tmp/*'


## Umount all
echo '[INFO] Umount all'
## Display all process details access /proc
sudo LANG=C chroot $FILESYSTEM_ROOT fuser -vm /proc
## Kill the processes
sudo LANG=C chroot $FILESYSTEM_ROOT fuser -km /proc || true
## Wait fuser fully kill the processes
sleep 15
sudo umount $FILESYSTEM_ROOT/proc || true

## Prepare empty directory to trigger mount move in initramfs-tools/mount_loop_root, implemented by patching
sudo mkdir $FILESYSTEM_ROOT/host



