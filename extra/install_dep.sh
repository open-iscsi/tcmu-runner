#!/bin/sh
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
		$SUDO yum install -y cmake make gcc libnl3 glib2 zlib kmod
		$SUDO yum install -y libnl3-devel glib2-devel zlib-devel kmod-devel

		# for glusterfs
		$SUDO yum install -y glusterfs-api glusterfs-api-devel
		# for ceph
		$SUDO yum install -y librados2 librados2-devel librbd1
		yum search librbd-devel | grep -q "N/S matched" && LIBRBD=librbd || LIBRBD=librbd1
	        $SUDO yum install -y $LIBRBD-devel
		;;
  ubuntu|debian)
		# for generic
		$SUDO apt-get install cmake make gcc libnl-3-dev libnl-genl-3-dev libglib2.0-dev zlib1g-dev libkmod-dev

		# for glusterfs
		$SUDO apt-get install glusterfs-common
		# for ceph
		$SUDO apt-get install librados2 librados-dev
		$SUDO apt-get install librbd1 librbd-dev
	*)
		echo "TODO: only fedora/rhel/centos/ubuntu/debian are supported for now!"
		;;
	esac
else
	echo "TODO: only Linux is supported for now!"
	exit 1
fi
