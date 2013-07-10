# Configuration

VERSION="v1.6i"
USELIBWRAP=1	# Use libwrap?
PREFIX=/usr/local

MAN=sslh.8.gz	# man page name

# End of configuration -- the rest should take care of
# itself

CC = gcc
CFLAGS=-Wall

#LIBS=-lnet
LIBS=

ifneq ($(strip $(USELIBWRAP)),)
	LIBS:=$(LIBS) -lwrap
	CFLAGS:=$(CFLAGS) -DLIBWRAP
endif

all: sslh $(MAN)

sslh: sslh.c Makefile
	$(CC) $(CFLAGS) -D'VERSION=$(VERSION)' -o sslh sslh.c $(LIBS)
	strip sslh

$(MAN): sslh.pod Makefile
	pod2man --section=8 --release=$(VERSION) --center=" " sslh.pod | gzip -9 - > $(MAN)

# generic install: install binary and man page
install: sslh $(MAN)
	install -D sslh $(PREFIX)/sbin/sslh
	install -D -m 0644 $(MAN) $(PREFIX)/share/man/man8/$(MAN)

# "extended" install for Debian: install startup script
install-debian: install sslh $(MAN)
	sed -e "s+^PREFIX=+PREFIX=$(PREFIX)+" scripts/etc.init.d.sslh > /etc/init.d/sslh
	chmod 755 /etc/init.d/sslh
	cp scripts/etc.default.sslh /etc/default/sslh
	update-rc.d sslh defaults

uninstall:
	rm -f $(PREFIX)/sbin/sslh $(PREFIX)/share/man/man8/$(MAN) /etc/init.d/sslh /etc/default/sslh
	update-rc.d sslh remove

clean:
	rm -f sslh $(MAN)
