#!/bin/bash
#
# Userspace side of the LIO TCM-User backstore
#
# For now only fedora, rhel and centos systems are supported

if test $(id -u) != 0 ; then
	SUDO=sudo
fi

if [ y`uname`y = yLinuxy ]; then
	source /etc/os-release
	case $ID in
	fedora|rhel|centos)
		# for generic
		$SUDO yum install -y cmake make gcc
		$SUDO yum install -y libnl3
		$SUDO yum install -y libnl3-devel
		$SUDO yum install -y glib2
		$SUDO yum install -y glib2-devel
	        $SUDO yum install -y zlib
		$SUDO yum install -y zlib-devel
		$SUDO yum install -y kmod
		$SUDO yum install -y kmod-devel
		$SUDO yum install -y gperftools-devel

		# for glusterfs
		$SUDO yum install -y glusterfs-api
		$SUDO yum install -y glusterfs-api-devel
		# for ceph
		$SUDO yum install -y librados2
		$SUDO yum install -y librados2-devel
		$SUDO yum install -y librbd1
		yum search librbd-devel | grep -q "N/S matched" && LIBRBD=librbd || LIBRBD=librbd1
	        $SUDO yum install -y $LIBRBD-devel
		;;
	debian)
		# Update APT cache
		$SUDO apt update
		
		# for generic
		$SUDO apt install -y cmake make gcc
		$SUDO apt install -y zlib1g kmod
		$SUDO apt install -y libnl-3-dev
		$SUDO apt install -y libnl-genl-3-dev
		$SUDO apt install -y libglib2.0-0
		$SUDO apt install -y libkmod-dev
		$SUDO apt install -y libgoogle-perftools-dev
		
		# for glusterfs
		$SUDO apt install -y libglusterfs-dev
		
		# for ceph
		$SUDO apt install -y librados2
		$SUDO apt install -y librbd-dev
		;;
	sles|opensuse-tumbleweed)
		# for generic
		$SUDO zypper install -y cmake make gcc
		$SUDO zypper install -y libnl3-200
		$SUDO zypper install -y glib2
		$SUDO zypper install -y zlib
		$SUDO zypper install -y kmod
		$SUDO zypper install -y libnl3-devel
		$SUDO zypper install -y glib2-devel
		$SUDO zypper install -y zlib-devel
		$SUDO zypper install -y libkmod-devel
		$SUDO zypper install -y gperftools-devel

		#for glusterfs
		$SUDO zypper install -y glusterfs
		$SUDO zypper install -y glusterfs-devel
		#for ceph
		$SUDO zypper install -y librbd-devel
		$SUDO zypper install -y librados-devel
		$SUDO zypper install -y librados2
		;;
	*)
		echo "TODO: distro not supported for now!"
		;;
	esac
else
	echo "TODO: only Linux is supported for now!"
	exit 1
fi
