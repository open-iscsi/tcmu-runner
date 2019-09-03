#!/bin/bash

if [ "$1" == "--help" -o "$1" == "help" ]; then
	echo ""
	echo "  USAGE:"
	echo ""
	echo "  # cd tcmu-runner/extra/"
	echo "  # ./make_runnerdeb.sh [-Dwith-<rbd|glfs|qcow|zbc|fbo>=false]"
	echo ""
	echo "  Will build the Debian package in top dir by using the HEAD commit ID as default."
	echo ""
	exit
fi

TOPDIR=`pwd`/../

VERSION=`git describe --tags --match "v[0-9]*"`
VERSION=`echo $VERSION | sed "s/-/./g"`
VERSION=`echo $VERSION | sed "s/v//"`

cmake $TOPDIR -DSUPPORT_SYSTEMD=ON -DCMAKE_INSTALL_PREFIX=/usr -DCPACK_DEBIAN_PACKAGE_VERSION=$VERSION "$@"
(cd $TOPDIR ; make package)
