# Configuration

USELIBWRAP=1	# Use libwrap?


# End of configuration -- the rest should take care of
# itself

CC = gcc

#LIBS=-lnet
LIBS=

ifneq ($(strip $(USELIBWRAP)),)
	LIBS:=$(LIBS) -lwrap
	CFLAGS=-DLIBWRAP
endif

all:
	$(CC) $(CFLAGS) -o sslh sslh.c $(LIBS)
	strip sslh


