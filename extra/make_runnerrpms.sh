#!/bin/sh

if [ "$1" == "--help" -o "$1" == "help" ]; then
	echo ""
	echo "  USAGE:"
	echo ""
	echo "  # cd tcmu-runner/extra/"
	echo "  # ./make_runnerrpms.sh [--without (rbd|glfs|qcow|zbc|fbo|tcmalloc)]"
	echo ""
	echo "  Will build the RPMs in current dir by using the HEAD commit ID as default."
	echo ""
	exit
fi

TOPDIR=`pwd`/../

if [ ! -e $TOPDIR/.git ]; then
	echo ""
	echo "For now this will only support the git repo code."
	echo ""
	exit
fi

VERSION=`git describe --tags --match "v[0-9]*"`
VERSION=`echo $VERSION | sed "s/-/./g"`
VERSION=`echo $VERSION | sed "s/v//"`
TCMURUNNER_TAR=tcmu-runner-$VERSION.tar.gz
rpmbuild_path=`pwd`/rpmbuild

# Try to clear the old rpmbuild data.
if [ -e $rpmbuild_path ]; then
	rm -rf $rpmbuild_path/*
fi

mkdir -p $rpmbuild_path/BUILD
mkdir -p $rpmbuild_path/SPECS
mkdir -p $rpmbuild_path/RPMS
mkdir -p $rpmbuild_path/SRPMS
mkdir -p $rpmbuild_path/SOURCES

cp ../tcmu-runner.spec $rpmbuild_path/SPECS/
SPEC=$rpmbuild_path/SPECS/tcmu-runner.spec

# Replace the Version
sed -i "s/Version:.*$/Version:       ${VERSION}/" $SPEC

# Delete all the _RC code if exists
LN=`grep -n "define" $SPEC |grep _RC | awk -F: '{print $1}'`
sed -i "${LN}d" $SPEC
sed -i "s/%{?_RC:%{_RC}}/0/g" $SPEC
sed -i "s/%{?_RC:-%{_RC}}//g" $SPEC

# Generate the source package
TMPDIR=/tmp/tcmu-runner-build
PKG_NAME=tcmu-runner-$VERSION
mkdir -p $TMPDIR/$PKG_NAME
git clone $TOPDIR/.git $TMPDIR/$PKG_NAME
rm -rf $TMPDIR/$PKG_NAME/.git*
cd $TMPDIR
tar -czvf $rpmbuild_path/SOURCES/$TCMURUNNER_TAR $PKG_NAME 2&> /dev/null
cd $TOPDIR/extra
rm -rf $TMPDIR

# Build the RPMs
rpmbuild --define="_topdir $rpmbuild_path" -ba $rpmbuild_path/SPECS/tcmu-runner.spec "$@"
