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

