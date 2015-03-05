# tcmu-runner

A daemon that handles the userspace side of the LIO TCM-User backstore.

## Development status

tcmu-runner is alpha-level software (not all required features implemented yet) with the goal of being feature complete by June 2015.

## Background

[LIO](http://linux-iscsi.org/wiki/Main_Page) is the [SCSI](http://en.wikipedia.org/wiki/SCSI) [target](http://en.wikipedia.org/wiki/SCSI_initiator_and_target) in the [Linux kernel](http://kernel.org). It is entirely kernel code, and allows exported SCSI [logical units (LUNs)](http://en.wikipedia.org/wiki/Logical_unit_number) to be backed by regular files or block devices. But, if we want to get fancier with the capabilities of the device we're emulating, the kernel is not necessarily the right place. While there are userspace libraries for compression, encryption, and clustered storage solutions like [Ceph](http://ceph.com/) or [Gluster](http://www.gluster.org/), these are not accessible from the kernel.

The TCMU userspace-passthrough backstore allows a userspace process to handle requests to a LUN. But since the kernel-user interface that TCMU provides must be fast and flexible, it is complex enough that we'd like to avoid each  userspace handler having to write boilerplate code.

**tcmu-runner** handles the messy details of the TCMU interface -- UIO, netlink, pthreads, and DBus -- and exports a more friendly C plugin module API. Modules using this API are called "TCMU handlers". Handler authors can write code just to handle the SCSI commands as desired, and can also link with whatever userspace libraries they like.

## Usage example

One goal of TCMU is that configuring a userspace-backed LUN should be as easy as configuring a kernel-backed LUN. We're not quite there yet. This will require cooperation with the LIO configuration tool, `targetcli`. `targetcli` should list user-backed backstores along with the built-in kernel backstores, and ensure tcmu-runner is started if a user-backed backstore is created.

## Info for potential contributors and handler authors

### License

tcmu-runner is [Apache 2.0 licensed](http://www.apache.org/licenses/LICENSE-2.0).

### Development

We encourage pull requests and issues tracking via Github, and the [target-devel mailing list](http://vger.kernel.org/vger-lists.html#target-devel) may be used for discussion.

### Getting started

##### Building tcmu-runner

1. Clone this repo.
1. Type `make`. Since we don't yet have a build system beyond make, if it doesn't work, it's probably because some development headers need to be installed, either for tcmu-runner or one of the included handlers.

##### Creating a LIO user-backed storage object in configfs

If using targetcli-fb on Fedora 21, there is a `user` backstore type, and you can create one with configstring, size, name, and pass level using the `/backstores/user create` command. Otherwise, it must be done by hand:

1. Ensure `target_core_user` module is loaded.
2. Create the HBA (user_1) and the storage object (test): `mkdir -p /sys/kernel/config/target/core/user_1/test`
3. Go to that directory: `cd /sys/kernel/config/target/core/user_1/test`
4. Set configuration values
  1. Set size (in bytes): `echo -n dev_size=16777216 > control`
  2. Set pass level. 0 is all SCSI commands, 1 is just block-related SCSI commands: `echo -n pass_level=1 > control`
  3. Set configstring. See [tcmu-design.txt](https://github.com/torvalds/linux/blob/master/Documentation/target/tcmu-design.txt#L177). If we wanted our new device to be handled by the "baz" handler, we might run:  `echo -n dev_config=tcm-user/1/test/baz/addl_info_for_baz_handler > control`
  4. Enable the storage object: `echo -n 1 > enable`
  5. Verify everything worked. There should be an entry in `/sys/class/uio`.

To delete:

1. `rmdir /sys/kernel/config/target/core/user_1/test`
2. `rmdir /sys/kernel/config/target/core/user_1`

##### Running tcmu-runner
Run it from the command line as root. It should print the number of handlers and devices found. It also will print a message if new devices are added or removed.
