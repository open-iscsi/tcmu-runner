# tcmu-runner

A daemon that handles the userspace side of the LIO TCM-User backstore.

## Development status

tcmu-runner is beta-level software with the goal of hitting 1.0 by November 2015.

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

We encourage pull requests and issues tracking via Github, and the [target-devel mailing list](mailto:target-devel@vger.kernel.org) ([list info](http://vger.kernel.org/vger-lists.html#target-devel)) may be used for discussion.

### Getting started

##### Building tcmu-runner

1. Install cmake.
1. Clone this repo.
1. Install development packages for dependencies: libnl3, libglib2 (or glib2-devel on Fedora), libpthread, libdl, libkmod, libgfapi (Gluster), zlib.
1. Type `cmake .`.
1. Type `make`.

##### Running tcmu-runner

1. Copy `tcmu-runner.conf` to `/etc/dbus-1/system.d/`. This allows tcmu-runner to be on the system bus, which is privileged.
1. If using systemd, copy `org.kernel.TCMUService1.service` to `/usr/share/dbus-1/system-services/` and `tcmu-runner.service` to `/lib/systemd/system`.
1. Or, run it from the command line as root. It should print the number of handlers and devices found.

##### Creating a LIO user-backed storage object in configfs

Support for creating user backstores via targetcli is under development, but for now:

1. Ensure `target_core_user` kernel module is loaded.
2. Create the HBA (user_1) and the storage object (test): `mkdir -p /sys/kernel/config/target/core/user_1/test`
3. Go to that directory: `cd /sys/kernel/config/target/core/user_1/test`
4. Set configuration values
  1. Set size (in bytes): `echo -n dev_size=16777216 > control`
  3. Set configstring. See [tcmu-design.txt](https://github.com/torvalds/linux/blob/master/Documentation/target/tcmu-design.txt#L177), but note that the TCMU backstore driver already knows and will prepend the "tcm-user/hba_num/device_name" part. Therefore, if we wanted our new device to be handled by the "baz" handler, we would give subtype and path by running:  `echo -n dev_config=baz/addl_info_for_baz_handler > control`
  4. Enable the storage object: `echo -n 1 > enable`
  5. Verify everything worked. There should be an entry in `/sys/class/uio`.

To delete:

1. `rmdir /sys/kernel/config/target/core/user_1/test`
2. `rmdir /sys/kernel/config/target/core/user_1`

### Writing a TCMU handler

#### libtcmu and tcmu-runner

There are two different ways to write a TCMU handler. The primary
difference is who is responsible for the event loop.

##### tcmu-runner plugin handler

With a tcmu-runner handler, tcmu-runner is in charge of the event loop
for your plugin, and your handler's `handle_cmd` function is called
repeatedly to respond to each incoming SCSI command. While your
handler sees all SCSI commands, there are helper functions provided
that save each handler from writing boilerplate code for mandatory
SCSI commands, if desired.

The `glfs`, `qcow`, and `file` handlers are examples of this type.

##### tcmulib

If you want to add handling of TCMU devices to an existing daemon or
other program that already is processing its own event loop, the best
option is to use tcmulib directly. This requires your code to keep
track of tcmulib's file descriptors. While tcmulib's 'master' file
descriptor must be handled with `tcmulib_master_fd_ready()`
single-threadedly, per-device fds can be handled on the main thread
(with `tcmulib_get_next_command` and `tcmulib_command_complete`) or
separate threads if desired. SCSI command-processing helper functions
are still available for use.

`tcmu-runner` itself uses tcmulib in this manner and may be used as an
example of multi-threaded tcmulib use. The `consumer.c` example
demonstrates single-threaded tcmulib processing.
