Frequently Asked Questions
==========================

When something doesn't work, look up here... and if it still
doesn't work, report how what was suggested here went.

It's also worth reading [how to ask
questions](http://www.catb.org/~esr/faqs/smart-questions.html)
before posting on the mailing list or opening an issue in
Github.

Getting more info
=================

In general, if something doesn't work, you'll want to run
`sslh` with lots of logging, and the logging directly in
the terminal (Otherwise, logs are sent to `syslog`, and
usually end up in `/var/log/auth.log`). You will achieve
this by running `sslh` in foreground with verbose:

```
sslh -v 1 -f -F myconfig.cfg
```

Higher values of `verbose` produce more information. 1 is
usually sufficient. 2 will also print incoming packets used
for probing.

forward to [PROBE] failed:connect: Connection refused
=====================================================

Usually this means `sslh` is configured to forward a
protocol somewhere, but no service is listening on the
target address. Check your `sslh` configuration, check the
corresponding server really is listening and running.
Finally, check the server is listening where you expect it
to:

```
netstat -lpt
```

I get a segmentation fault!
===========================

Well, it's not yours (fault): a segfault is always a bug in
the programme. Usually standard use cases are well tested,
so it may be related to something unusual in your
configuration, or even something wrong, but it should still
never result in a segfault.

Thankfully, when they are deterministic, segfaults are
usually fairly easy to fix if you're willing to run a few
diagnostics to help the developer.

First, make sure you have debug symbols:
```
$ file sslh-select
sslh-select: ELF 64-bit LSB pie executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 3.2.0, BuildID[sha1]=a758ac75ff11f1ace577705b4d6627e301940b59, with debug_info, not stripped
```

Note `with debug_info, not stripped` at the end. If you
don't have that, your distribution stripped the binary: you
will need to get the source code and compile it yourself
(that way, you will also get the latest version).

Install `valgrind` and run `sslh` under it:

```
valgrind --leak-check=full ./sslh-fork -v 2 -f -F yourconfig.cfg
```

Report the full output to the mailing list or github.
Valgrind is very powerful and gives precise hints of what is
wrong and why. For example on `sslh` issue
(#273)[https://github.com/yrutschle/sslh/issues/273]:

```
sudo valgrind --leak-check=full ./sslh-fork -v 2 -f -F /etc/sslh.cfg
==20037== Memcheck, a memory error detector
==20037== Copyright (C) 2002-2017, and GNU GPL'd, by Julian Seward et al.
==20037== Using Valgrind-3.15.0 and LibVEX; rerun with -h for copyright info
==20037== Command: ./sslh-fork -v 2 -f -F /etc/sslh.cfg
==20037==
sslh-fork v1.21b-1-g2c93a01-dirty started
--20037-- WARNING: unhandled arm-linux syscall: 403
--20037-- You may be able to write your own handler.
--20037-- Read the file README_MISSING_SYSCALL_OR_IOCTL.
--20037-- Nevertheless we consider this a bug.  Please report
--20037-- it at http://valgrind.org/support/bug_reports.html.
==20040== Conditional jump or move depends on uninitialised value(s)
==20040==    at 0x112A3C: parse_tls_header (tls.c:162)
==20040==    by 0x111CEF: is_tls_protocol (probe.c:214)
==20040==    by 0x11239F: probe_client_protocol (probe.c:366)
==20040==    by 0x10A8F7: start_shoveler (sslh-fork.c:98)
==20040==    by 0x10AE9B: main_loop (sslh-fork.c:200)
==20040==    by 0x1114FB: main (sslh-main.c:322)
==20040==
```

Here we see that something wrong is happening at `tls.c`
line 162, and it's linked to an uninitialised value.

