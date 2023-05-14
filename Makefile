
VERSION=$(shell ./genver.sh -r)

# Configuration -- you probably need to `make clean` if you
# change any of these
ENABLE_SANITIZER= # Enable ASAN/LSAN/UBSAN
ENABLE_REGEX=1  # Enable regex probes
USELIBCONFIG=1	# Use libconfig? (necessary to use configuration files)
USELIBWRAP?=	# Use libwrap?
USELIBCAP=	# Use libcap?
USESYSTEMD=     # Make use of systemd socket activation
USELIBBSD?=     # Use libbsd (needed to update process name in `ps`)
COV_TEST= 	# Perform test coverage?
PREFIX?=/usr
BINDIR?=$(PREFIX)/sbin
MANDIR?=$(PREFIX)/share/man/man8

MAN=sslh.8.gz	# man page name

# End of configuration -- the rest should take care of
# itself

ifneq ($(strip $(ENABLE_SANITIZER)),)
    CFLAGS_SAN=-fsanitize=address -fsanitize=leak -fsanitize=undefined
endif

ifneq ($(strip $(COV_TEST)),)
    CFLAGS_COV=-fprofile-arcs -ftest-coverage
endif

CC ?= gcc
AR ?= ar
CFLAGS ?=-Wall -O2 -DLIBPCRE -g $(CFLAGS_COV) $(CFLAGS_SAN)

LIBS=-lm -lpcre2-8
OBJS=sslh-conf.o common.o log.o sslh-main.o probe.o http.o tls.o argtable3.o collection.o gap.o tcp-probe.o
OBJS_A=libsslh.a
FORK_OBJS=sslh-fork.o $(OBJS_A)
SELECT_OBJS=processes.o udp-listener.o sslh-select.o hash.o tcp-listener.o $(OBJS_A)
EV_OBJS=processes.o udp-listener.o sslh-ev.o hash.o tcp-listener.o $(OBJS_A)

CONDITIONAL_TARGETS=

ifneq ($(strip $(USELIBWRAP)),)
	LIBS:=$(LIBS) -lwrap
	CPPFLAGS+=-DLIBWRAP
endif

ifneq ($(strip $(ENABLE_REGEX)),)
	CPPFLAGS+=-DENABLE_REGEX
endif

ifneq ($(strip $(USELIBCONFIG)),)
	LIBS:=$(LIBS) -lconfig
	CPPFLAGS+=-DLIBCONFIG
endif

ifneq ($(strip $(USELIBCAP)),)
	LIBS:=$(LIBS) -lcap
	CPPFLAGS+=-DLIBCAP
endif

ifneq ($(strip $(USESYSTEMD)),)
        LIBS:=$(LIBS) -lsystemd
        CPPFLAGS+=-DSYSTEMD
	CONDITIONAL_TARGETS+=systemd-sslh-generator
endif

ifneq ($(strip $(USELIBBSD)),)
        LIBS:=$(LIBS) -lbsd
        CPPFLAGS+=-DLIBBSD
endif


all: sslh $(MAN) echosrv $(CONDITIONAL_TARGETS)

%.o: %.c %.h version.h
	$(CC) $(CFLAGS) $(CPPFLAGS) -c $< -o $@

$(OBJS_A): $(OBJS)
	$(AR) rcs $(OBJS_A) $(OBJS)

version.h:
	./genver.sh >version.h

sslh: sslh-fork sslh-select sslh-ev

$(OBJS) $(FORK_OBJS) $(SELECT_OBJS) $(EV_OBJS): argtable3.h collection.h common.h gap.h hash.h log.h probe.h processes.h sslh-conf.h tcp-listener.h tcp-probe.h http.h tls.h udp-listener.h version.h


sslh-conf.c sslh-conf.h: sslhconf.cfg
	conf2struct sslhconf.cfg

sslh-fork: version.h Makefile $(FORK_OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o sslh-fork $(FORK_OBJS) $(LIBS)

sslh-select: version.h $(SELECT_OBJS) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o sslh-select $(SELECT_OBJS) $(LIBS)

sslh-ev: version.h $(EV_OBJS) Makefile
	$(CC) $(CFLAGS) $(LDFLAGS) -o sslh-ev $(EV_OBJS) $(LIBS) -lev

systemd-sslh-generator: systemd-sslh-generator.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o systemd-sslh-generator systemd-sslh-generator.o -lconfig

echosrv-conf.c echosrv-conf.h: echosrv.cfg
	conf2struct echosrv.cfg

echosrv: version.h echosrv-conf.c echosrv.o echosrv-conf.o argtable3.o
	$(CC) $(CFLAGS) $(LDFLAGS) -o echosrv echosrv.o echosrv-conf.o argtable3.o $(LIBS)

$(MAN): sslh.pod Makefile
	pod2man --section=8 --release=$(VERSION) --center=" " sslh.pod | gzip -9 - > $(MAN)

# Create release: export clean tree and tag current
# configuration
release:
	git archive master --prefix="sslh-$(VERSION)/" | gzip > /tmp/sslh-$(VERSION).tar.gz
	gpg --detach-sign --armor /tmp/sslh-$(VERSION).tar.gz

# Build docker image
docker:
	docker image build -t "sslh:${VERSION}" .
	docker image tag "sslh:${VERSION}" sslh:latest

docker-clean:
	yes | docker image rm "sslh:${VERSION}" sslh:latest
	yes | docker image prune

# generic install: install binary and man page
install: sslh $(MAN)
	mkdir -p $(DESTDIR)/$(BINDIR)
	mkdir -p $(DESTDIR)/$(MANDIR)
	install -p sslh-fork $(DESTDIR)/$(BINDIR)/sslh
	install -p -m 0644 $(MAN) $(DESTDIR)/$(MANDIR)/$(MAN)

# "extended" install for Debian: install startup script
install-debian: install sslh $(MAN)
	sed -e "s+^PREFIX=+PREFIX=$(PREFIX)+" scripts/etc.init.d.sslh > /etc/init.d/sslh
	chmod 755 /etc/init.d/sslh
	update-rc.d sslh defaults

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/sslh $(DESTDIR)$(MANDIR)/$(MAN) $(DESTDIR)/etc/init.d/sslh $(DESTDIR)/etc/default/sslh
	update-rc.d sslh remove

distclean: clean
	rm -f tags sslh-conf.[ch] echosrv-conf.[ch] cscope.*

clean:
	rm -f sslh-fork sslh-select sslh-ev echosrv version.h $(MAN) systemd-sslh-generator *.o *.gcov *.gcno *.gcda *.png *.html *.css *.info

tags:
	ctags --globals -T *.[ch]

cscope:
	-find . -name "*.[chS]" >cscope.files
	-cscope -b -R

test:
	./t
