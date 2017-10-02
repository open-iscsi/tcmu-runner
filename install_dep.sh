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
	        $DUDO yum install -y $LIBRBD-devel
		;;
	*)
		echo "TODO: only fedora/rhel/centos are supported for now!"
		;;
	esac
else
	echo "TODO: only Linux is supported for now!"
	exit 1
fi
