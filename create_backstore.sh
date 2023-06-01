#!/bin/bash

set -e

user_dir="user_1"
dev_config="foo/xxx"

if [ -d /sys/kernel/config/target/core/$user_dir/test ]; then
  echo "backstore already exists - remove it with delete_backstore.sh"
  exit 1
fi

mkdir -p /sys/kernel/config/target/core/$user_dir/test
echo "dev_size=1048576,hw_max_sectors=256,hw_block_size=4096,dev_config=$dev_config,nl_reply_supported=-1" > /sys/kernel/config/target/core/$user_dir/test/control
echo "1" > /sys/kernel/config/target/core/$user_dir/test/enable
echo "created backstore"
exit 0
