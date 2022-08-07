#!/bin/bash

# Finds the name of the uio device pertaining to the TCMU backstore
# "test/foo". The uio device - e.g. uio0 - is printed to stdout.

for d in /sys/class/uio/*/name;
do
  cfgstring=`cat $d`
  if [[ $cfgstring == tcm-user/*/test/foo/xxx ]]; then
    uio=`echo $d | grep -oP "uio\d"`
    echo -n $uio
    exit 0
  fi
done
exit 1
