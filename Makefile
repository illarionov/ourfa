SHELL=/bin/sh

CC?=gcc
AR?=ar
RANLIB?=ranlib
OBJCOPY?=objcopy
#CFLAGS?= -W -Wall -O2 -DNDEBUG -s
#CFLAGS=-W -Wall -g -O0 -fstack-protector
CFLAGS+= -DNDEBUG -s

PREFIX=/usr/local
LDFLAGS?=-L/usr/local/lib

XML2_CFLAGS?=	`xml2-config --cflags`
XML2_LIBS?=	`xml2-config --libs`
ICONV_CFLAGS?=	-I/usr/local/include
ICONV_LIBS?=	-L/usr/local/lib -liconv

DESTDIR?=/
PREFIX?=netup/utm5

OBJS= hash.o \
      xmlapi.o \
      pkt.o \
      error.o \
      connection.o \
      func_call.o \
      ssl_ctx.o \
      asprintf.o \
      dtoa.o

all: libourfa.a ourfa_client

ourfa_client: ourfa.h libourfa.a client.o client_dump.o client_datafile.o
	$(CC) $(CFLAGS) $(XML2_CFLAGS) $(ICONV_CFLAGS) \
	  -o ourfa_client \
	  client.o client_dump.o client_datafile.o \
	  $(LDFLAGS) -L. -lourfa -lssl -lcrypto $(XML2_LIBS) $(ICONV_LIBS)

libourfa.a: $(OBJS)
	rm -f libourfa.a
	$(AR) cq libourfa.a $(OBJS)
	$(RANLIB) libourfa.a

install: ourfa_client
	if ( test ! -d $(PREFIX)/bin ) ; then mkdir -p $(PREFIX)/bin ; fi
	if ( test ! -d $(PREFIX)/lib ) ; then mkdir -p $(PREFIX)/lib ; fi
	if ( test ! -d $(PREFIX)/include ) ; then mkdir -p $(PREFIX)/include ; fi
	cp -f ourfa_client $(PREFIX)/bin/ourfa_client
	chmod a+x $(PREFIX)/bin/ourfa_client
	cp -f ourfa.h $(PREFIX)/include
	chmod a+r $(PREFIX)/include/ourfa.h
	cp -f libourfa.a $(PREFIX)/lib
	chmod a+r $(PREFIX)/lib/libourfa.a
clean:
	rm -f *.o ourfa_client libourfa.a

DISTNAME=ourfa-521008001

dist:
	rm -f $(DISTNAME)
	ln -s -f . $(DISTNAME)
	git log --no-merges > $(DISTNAME)/Changelog
	tar czvf $(DISTNAME).tar.gz \
	   $(DISTNAME)/Makefile \
	   $(DISTNAME)/Makefile.mingw \
	   $(DISTNAME)/Makefile.msvc \
	   $(DISTNAME)/README \
	   $(DISTNAME)/Changelog \
	   $(DISTNAME)/asprintf.c \
	   $(DISTNAME)/freebsd/ourfa/Makefile \
	   $(DISTNAME)/freebsd/ourfa/distinfo \
	   $(DISTNAME)/freebsd/ourfa/pkg-descr \
	   $(DISTNAME)/freebsd/p5-Ourfa/Makefile \
	   $(DISTNAME)/freebsd/p5-Ourfa/distinfo \
	   $(DISTNAME)/freebsd/p5-Ourfa/pkg-descr \
	   $(DISTNAME)/freebsd/p5-Ourfa/pkg-plist \
	   $(DISTNAME)/client.c \
	   $(DISTNAME)/client_datafile.c \
	   $(DISTNAME)/client_dump.c \
	   $(DISTNAME)/connection.c \
	   $(DISTNAME)/dtoa.c \
	   $(DISTNAME)/error.c \
	   $(DISTNAME)/example.sh \
	   $(DISTNAME)/func_call.c \
	   $(DISTNAME)/hash.c \
	   $(DISTNAME)/ourfa.h \
	   $(DISTNAME)/pkt.c \
	   $(DISTNAME)/ssl_ctx.c \
	   $(DISTNAME)/xmlapi.c \
	   `eval "sed 's|^|$(DISTNAME)/ourfa-perl/|' ourfa-perl/MANIFEST"`
	rm $(DISTNAME)

asprintf.o: asprintf.c
	$(CC) $(CFLAGS) -c asprintf.c
pkt.o: pkt.c ourfa.h
	$(CC) $(CFLAGS) -c pkt.c
error.o: error.c ourfa.h
	$(CC) $(CFLAGS) -c error.c
connection.o: connection.c ourfa.h
	$(CC) $(CFLAGS) -c connection.c
func_call.o: func_call.c ourfa.h
	$(CC) $(CFLAGS) -c func_call.c
ssl_ctx.o: ssl_ctx.c ourfa.h
	$(CC) $(CFLAGS) -c ssl_ctx.c
hash.o: hash.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c hash.c
xmlapi.o: xmlapi.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c xmlapi.c
client.o: client.c ourfa.h
	$(CC) $(CFLAGS) $(ICONV_CFLAGS) -c client.c
client_dump.o: client_dump.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c client_dump.c
client_datafile.o: client_dump.o client_datafile.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c client_datafile.c
dtoa.o: dtoa.c
	$(CC) $(CFLAGS) -DIEEE_8087 -UUSE_LOCALE -o dtoa_orig.o -c dtoa.c
	$(OBJCOPY) --redefine-sym strtod=ourfa_strtod_c --localize-symbol dtoa dtoa_orig.o dtoa.o

