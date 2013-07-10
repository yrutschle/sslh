# Configuration

VERSION="v1.12"
USELIBCONFIG=1	# Use libconfig? (necessary to use configuration files)
USELIBWRAP=	# Use libwrap?
COV_TEST= 	# Perform test coverage?
PREFIX=/usr/local

MAN=sslh.8.gz	# man page name

# End of configuration -- the rest should take care of
# itself

ifneq ($(strip $(COV_TEST)),)
    CFLAGS_COV=-fprofile-arcs -ftest-coverage
endif

CC = gcc
CFLAGS=-Wall -g $(CFLAGS_COV)

LIBS=
OBJS=common.o sslh-main.o probe.o

ifneq ($(strip $(USELIBWRAP)),)
	LIBS:=$(LIBS) -lwrap
	CFLAGS:=$(CFLAGS) -DLIBWRAP
endif

ifneq ($(strip $(USELIBCONFIG)),)
	LIBS:=$(LIBS) -lconfig
	CFLAGS:=$(CFLAGS) -DLIBCONFIG
endif

all: sslh $(MAN) echosrv

.c.o: *.h
	$(CC) $(CFLAGS) -D'VERSION=$(VERSION)' -c $<


sslh: $(OBJS) sslh-fork sslh-select

sslh-fork: $(OBJS) sslh-fork.o Makefile common.h
	$(CC) $(CFLAGS) -D'VERSION=$(VERSION)' -o sslh-fork sslh-fork.o $(OBJS) $(LIBS)
	#strip sslh-fork

sslh-select: $(OBJS) sslh-select.o Makefile common.h 
	$(CC) $(CFLAGS) -D'VERSION=$(VERSION)' -o sslh-select sslh-select.o $(OBJS) $(LIBS)
	#strip sslh-select

echosrv: $(OBJS) echosrv.o
	$(CC) $(CFLAGS) -o echosrv echosrv.o common.o $(LIBS)

$(MAN): sslh.pod Makefile
	pod2man --section=8 --release=$(VERSION) --center=" " sslh.pod | gzip -9 - > $(MAN)

# generic install: install binary and man page
install: sslh $(MAN)
	install -D sslh-fork $(PREFIX)/sbin/sslh
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
	rm -f sslh-fork sslh-select echosrv $(MAN) *.o *.gcov *.gcno *.gcda *.png *.html *.css *.info 

tags:
	ctags -T *.[ch]

test:
	./t

