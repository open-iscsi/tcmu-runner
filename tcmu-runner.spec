Name:          tcmu-runner
Summary:       A daemon that handles the userspace side of the LIO TCM-User backstore
Group:         System Environment/Kernel
License:       Apache 2.0
Version:       1.3.0
URL:           https://github.com/open-iscsi/tcmu-runner

%define _RC rc4
Release:       %{?_RC:%{_RC}}%{dist}
BuildRoot:     %(mktemp -udp %{_tmppath}/%{name}-%{version}%{?_RC:-%{_RC}})
Source:       %{name}-%{version}%{?_RC:-%{_RC}}.tar.gz
ExclusiveOS:   Linux

BuildRequires: cmake make gcc
BuildRequires: libnl3-devel glib2-devel zlib-devel kmod-devel
BuildRequires: glusterfs-api-devel librados2-devel librbd1-devel

Requires(pre): librados2, librbd1, kmod, zlib, libnl3, glib2, glusterfs-api

%description
A daemon that handles the userspace side of the LIO TCM-User backstore.

LIO is the SCSI target in the Linux kernel. It is entirely kernel code, and
allows exported SCSI logical units (LUNs) to be backed by regular files or
block devices. But, if we want to get fancier with the capabilities of the
device we're emulating, the kernel is not necessarily the right place. While
there are userspace libraries for compression, encryption, and clustered
storage solutions like Ceph or Gluster, these are not accessible from the
kernel.

The TCMU userspace-passthrough backstore allows a userspace process to handle
requests to a LUN. But since the kernel-user interface that TCMU provides
must be fast and flexible, it is complex enough that we'd like to avoid each
userspace handler having to write boilerplate code.

tcmu-runner handles the messy details of the TCMU interface -- UIO, netlink,
pthreads, and DBus -- and exports a more friendly C plugin module API. Modules
using this API are called "TCMU handlers". Handler authors can write code just
to handle the SCSI commands as desired, and can also link with whatever
userspace libraries they like.

%prep
%setup -n %{name}-%{version}%{?_RC:-%{_RC}}

%build
%{__cmake} -DSUPPORT_SYSTEMD=ON -DCMAKE_INSTALL_PREFIX=%{_usr} .
%{__make}

%install
%{__make} DESTDIR=%{buildroot} install

%clean
%{__rm} -rf ${buldroot}

%files
%defattr(-,root,root)
%{_bindir}/tcmu-runner
%dir %{_sysconfdir}/dbus-1/
%dir %{_sysconfdir}/dbus-1/system.d
%config %{_sysconfdir}/dbus-1/system.d/tcmu-runner.conf
%dir %{_datadir}/dbus-1/
%dir %{_datadir}/dbus-1/system-services/
%{_datadir}/dbus-1/system-services/org.kernel.TCMUService1.service
%{_unitdir}/tcmu-runner.service
%dir %{_usr}/lib64/tcmu-runner/
%{_usr}/lib64/tcmu-runner/*
%{_mandir}/man8/*
%doc README.md LICENSE
%{_usr}/lib64/*
%dir %{_sysconfdir}/tcmu/
%config %{_sysconfdir}/tcmu/tcmu.conf

%changelog
* Tue Oct 31 2017 Xiubo Li <lixiubo@cmss.chinamobile.com> - 1.3.0-rc4
- Initial tcmu-runner packaging
