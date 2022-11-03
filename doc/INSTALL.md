Compile and install
===================

Dependencies
------------

`sslh` uses:

* [libconfig](http://www.hyperrealm.com/libconfig/). For
  Debian this is contained in package `libconfig-dev`. You
can compile with or without it using USELIBCONFIG in the
Makefile.

* [libwrap](http://packages.debian.org/source/unstable/tcp-wrappers).
    For Debian, this is contained in packages
`libwrap0-dev`. You
can compile with or without it using USELIBWRAP in the
Makefile.

* [libsystemd](http://packages.debian.org/source/unstable/libsystemd-dev), in package `libsystemd-dev`.  You
can compile with or without it using USESYSTEMD in the
Makefile.

* [libcap](http://packages.debian.org/source/unstable/libcap-dev), in package `libcap-dev`. You can compile with or without it using USELIBCAP in the Makefile

* libbsd, to enable to change the process name (as shown in
  `ps`, so each forked process shows what protocol and what
  connection it is serving),
which requires `libbsd` at runtime, and `libbsd-dev` at
compile-time.

* libpcre2, in package `libpcre-dev`. You can compile
  with or without it using ENABLE_REGEX in the Makefile.

* libev-dev, in package `libev-dev`. If you build a binary
  specifically and do not build `sslh-ev`, you don't need
  this.


For OpenSUSE, these are contained in packages libconfig9 and
libconfig-dev in repository
<http://download.opensuse.org/repositories/multimedia:/libs/openSUSE_12.1/>

For Fedora, you'll need packages `libconfig` and
`libconfig-devel`:

	yum install libconfig libconfig-devel

If you want to rebuild `sslh-conf.c` (after a `make
distclean` for example), you will also need to add
[conf2struct](https://www.rutschle.net/tech/conf2struct/README.html)
(v1.5) to your path.


The test scripts are written in Perl, and will require
IO::Socket::INET6 (libio-socket-inet6-perl in Debian).

Compilation
-----------

After this, the Makefile should work:

	make install

There are a couple of configuration options at the beginning
of the Makefile: 

* `USELIBWRAP` compiles support for host access control (see
  `hosts_access(3)`), you will need `libwrap` headers and
  library to compile (`libwrap0-dev` in Debian).

* `USELIBCONFIG` compiles support for the configuration
  file. You will need `libconfig` headers to compile
  (`libconfig8-dev` in Debian).

*  `USESYSTEMD` compiles support for using systemd socket activation.
   You will need `systemd` headers to compile (`systemd-devel` in Fedora).

* `USELIBBSD` compiles support for updating the process name (as shown
  by `ps`).

Binaries
--------

The Makefile produces three different executables: `sslh-fork`,
`sslh-select` and `sslh-ev`:

* `sslh-fork` forks a new process for each incoming connection.
It is well-tested and very reliable, but incurs the overhead
of many processes.  
If you are going to use `sslh` for a "small" setup (less than
a dozen ssh connections and a low-traffic https server) then
`sslh-fork` is probably more suited for you. 

* `sslh-select` uses only one thread, which monitors all
  connections at once. It only incurs a 16 byte overhead per
connection.  Also, if it stops, you'll lose all connections,
which means you can't upgrade it remotely.  If you are going
to use `sslh` on a "medium" setup (a few hundreds of
connections), or if you are on a system where forking is
expensive (e.g. Windows), `sslh-select` will be better.

* `sslh-ev` is similar to `sslh-select`, but uses `libev` as
  a backend. This allows using specific kernel APIs that
allow to manage thousands of connections concurrently.

Installation
------------

* In general:

		make
		cp sslh-fork /usr/local/sbin/sslh
		cp basic.cfg /etc/sslh.cfg
                vi /etc/sslh.cfg

* For Debian:

		cp scripts/etc.init.d.sslh /etc/init.d/sslh
	
* For CentOS:

		cp scripts/etc.rc.d.init.d.sslh.centos /etc/rc.d/init.d/sslh


You might need to create links in /etc/rc<x>.d so that the server
start automatically at boot-up, e.g. under Debian:

	update-rc.d sslh defaults

