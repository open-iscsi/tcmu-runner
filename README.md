# tcmu-runner

A daemon that handles the userspace side of the LIO TCM-User backstore.

## Background

[LIO](http://linux-iscsi.org/wiki/Main_Page) is the [SCSI](http://en.wikipedia.org/wiki/SCSI) [target](http://en.wikipedia.org/wiki/SCSI_initiator_and_target) in the [Linux kernel](http://kernel.org). It is entirely kernel code, and allows exported SCSI [logical units (LUNs)](http://en.wikipedia.org/wiki/Logical_unit_number) to be backed by regular files or block devices. But, if we want to get fancier with the capabilities of the device we're emulating, the kernel is not necessarily the right place. While there are userspace libraries for compression, encryption, and clustered storage solutions like [Ceph](http://ceph.com/) or [Gluster](http://www.gluster.org/), these are not accessible from the kernel.

The TCMU userspace-passthrough backstore allows a userspace process to handle requests to a LUN. But since the kernel-user interface that TCMU provides must be fast and flexible, it is complex enough that we'd like to avoid each  userspace handler having to write boilerplate code.

**tcmu-runner** handles the messy details of the TCMU interface -- UIO, netlink, pthreads, and DBus -- and exports a more friendly C plugin module API. Modules using this API are called "TCMU handlers". Handler authors can write code just to handle the SCSI commands as desired, and can also link with whatever userspace libraries they like.

## Usage example

One goal of TCMU is that configuring a userspace-backed LUN should be as easy as configuring a kernel-backed LUN. We're not quite there yet. This will require cooperation with the LIO configuration tool, `targetcli`. `targetcli` should list user-backed backstores along with the built-in kernel backstores, and ensure tcmu-runner is started if a user-backed backstore is created.

## Info for potential contributors and handler authors

### License

tcmu-runner is [Apache 2.0 licensed](http://www.apache.org/licenses/LICENSE-2.0).

### Releases

Tarballs are available from https://fedorahosted.org/released/tcmu-runner/ .

### Development

We encourage pull requests and issues tracking via Github, and the [target-devel mailing list](mailto:target-devel@vger.kernel.org) ([list info](http://vger.kernel.org/vger-lists.html#target-devel)) may be used for discussion.

### Getting started

##### Building tcmu-runner

1. Clone this repo.
1. Type `./install_dep.sh` to install development packages for dependencies, or you can do it manually:
   * *Note:* Install cmake and other packages which usually ending with "-devel" or "-dev": libnl3, libglib2 (or glib2-devel on Fedora), libpthread, libdl, libkmod, libgfapi (Gluster), librbd1 (Ceph), zlib.
1. Type `cd tcmu-runner/`
1. Type `cmake .`
   * *Note:* tcmu-runner can be compiled without the Gluster or qcow handlers using the `-Dwith-glfs=false` and `-Dwith-qcow=false` cmake parameters respectively.
   * *Note:* If using systemd, `-DSUPPORT_SYSTEMD=ON -DCMAKE_INSTALL_PREFIX=/usr` should be passed to cmake, so files are installed to the correct location.
1. Type `make`
1. Type `make install`


##### Running tcmu-runner

1. Copy `tcmu-runner.conf` to `/etc/dbus-1/system.d/`. This allows tcmu-runner to be on the system bus, which is privileged.
1. If using systemd, copy `org.kernel.TCMUService1.service` to `/usr/share/dbus-1/system-services/` and `tcmu-runner.service` to `/lib/systemd/system`.
1. Or, run it from the command line as root. It should print the number of handlers and devices found.


##### Creating a LIO user-backed storage object with backstore specific tools

- Ceph:

If setting up tcmu-runner in a HA configuration, the ceph-iscsi-cli
(https://github.com/ceph/ceph-iscsi-cli) tool is the preferred management
tool.

Bug reports should be made to the tcmu-runner github:
https://github.com/open-iscsi/tcmu-runner/issues, but can be made to
ceph-users@ceph.com mailing list.

- Gluster:

Gluster management must be done with the gluster-block tools
(https://github.com/gluster/gluster-block).

Bug reports must be made to the gluster-block github:
https://github.com/gluster/gluster-block/issues

##### Creating a LIO user-backed storage object with targetcli-fb or configfs

Support for the user/tcmu backstore is supported in targetcli-fb/rtslib-fb:

https://github.com/open-iscsi/targetcli-fb
https://github.com/open-iscsi/rtslib-fb

1. Start targetcli

\# targetcli

2. Go to the user/tcmu backstore dir.

/> cd /backstores/

3. By default, tcmu-runner installs the file, zbc, glfs, qcow and rbd tcmu-runner handlers:

```
/backstores> ls
o- backstores .......................................................... [...]
  o- user:glfs .......................................... [Storage Objects: 0]
  o- user:qcow .......................................... [Storage Objects: 0]
  o- user:rbd ........................................... [Storage Objects: 0]
  o- user:file .......................................... [Storage Objects: 0]
  o- user:zbc ........................................... [Storage Objects: 0]
```

4. 'cd' to the handler you want to setup:

/backstores> cd user:rbd 

/backstores/user:rbd> create cfgstring=pool/rbd1;osd_op_timeout=30 name=rbd0 size=1G
Created user-backed storage object rbd0 size 1073741824.


Note that the cfgstring is handler specific. The format is:

- **rbd**: /pool_name/image_name[;osd_op_timeout=N;conf=N]
(osd_op_timeout is optional and N is in seconds)
(conf is optional and N is the path to the conf file)
- **qcow**: /path_to_file
- **glfs**: /volume@hostname/filename
- **file**: /path_to_file
- **zbc**: /[opt1[/opt2][...]@]path_to_file

For the zbc handler, the available options are shown in the table below.

| Option | Description | Default value |
| --- | --- | --- |
| model-**_type_** | Device model type, _HA_ for host aware or _HM_ for host managed | _HM_
| lba-**_size (B)_** | LBA size in bytes (512 or 4096) | 512
| zsize-**_size (MiB)_** | Zone size in MiB | 256 MiB
| conv-**_num_** | Number of conventional zones at LBA 0 (can be 0) | Number of zones corresponding to 1% of the device capacity
| open-**_num_** | Optimal (for host aware) or maximum (for host managed) number of open zones | 128

Example:
```
cfgstring=model-HM/zsize-128/conv-100@/var/local/zbc.raw
```

will create a host-managed disk with 128 MiB zones and 100 conventional zones,
stored in the file /var/local/zbc.raw.

5. The created backstore device can then be mapped to a LUN like traditional
backstores.

##### Logger setting and system configuration

- Logger setting:

There are 5 logging levels supported:

1. ERROR
2. WARNING
3. INFO
4. DEBUG
5. DEBUG SCSI CMD

And the default logging level is 3, if you want to change the default level,
uncomment the following line in /etc/tcmu/tcmu.conf and set your level number:

\# log_level = 3

The priority of the logdir setting can be managed via following options:

1. Cli argument
</br>eg: --tcmu_log_dir/-l `LOG_DIR_PATH` [Highest prio]
2. Environment variable
</br>eg: export TCMU_LOGDIR="/var/log/mylogdir/"
3. Configuration file
</br>eg: uncommenting and adjusting value of 'log_dir_path' at /etc/tcmu/tcmu.conf
4. Default logdir as hard coded i.e. '/var/log/' [Least prio]

- System configuration:

The default configuration file is installed into /etc/tcmu/tcmu.conf.

Tcmu-runner's configuration systems supports dynamic reloading without restarting
the daemon. To change values open /etc/tcmu/tcmu.conf, update the value, and then
close the file.

------------------------------

If your version of targetcli/rtslib does not support tcmu, setup can be done
manually through configfs:

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

------------------------------

### Writing a TCMU handler

#### libtcmu and tcmu-runner

There are two different ways to write a TCMU handler. The primary
difference is who is responsible for the event loop.

##### tcmu-runner plugin handler

There are two different ways to write a tcmu-runner plugin handler:

1. one can register .handle_cmd to take the full control of command handling
2. or else one can register .{read, write, flush, ...} to handle specific
   operations and .handle_cmd to override the generic handling if needed.

With the option 1, tcmu-runner is in charge of the event loop
for your plugin, and your handler's `handle_cmd` function is called
repeatedly to respond to each incoming SCSI command. While your
handler sees all SCSI commands, there are helper functions provided
that save each handler from writing boilerplate code for mandatory
SCSI commands, if desired.

The `file_optical` handler is an examples of this type.

With the option 2, tcmu-runner will be partially or fully in charge of the event
loop and SCSI command handling for your plugin, and your handler's registered
functions are called repeatedly to handle storage requests as required by the
upper SCSI layer, which will handle most of the SCSI commands for you.

* *Note:* If the .handle_cmd is also implemented by the handler, tcmu-runner will
try to pass through the commands to the handler first, if and only when the handler
won't support the commands it should return TCMU_NOT_HANDLED, then the tcmu-runner
will handle them in generic.

The `file_example` handler is an example of this type.

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
