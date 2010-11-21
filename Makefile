SHELL=/bin/sh

CC?=gcc
AR?=ar
CFLAGS?= -W -Wall -O2 -DNDEBUG -s
CFLAGS=-W -Wall -g -O0
#CFLAGS+= -DNDEBUG -s

PREFIX=/usr/local

LDFLAGS= -L/usr/local/lib -lssl -lcrypto

XML2_CFLAGS?=	`xml2-config --cflags`
XML2_LIBS?=	`xml2-config --libs`

DESTDIR?=/
PREFIX?=netup/utm5

OBJS= hash.o \
      xmlapi.o \
      pkt.o \
      error.o \
      connection.o \
      func_call.o \
      ssl_ctx.o

all: libourfa.a ourfa_client

ourfa_client: ourfa.h libourfa.a client.o client_dump.o
	$(CC) $(CFLAGS) $(XML2_CFLAGS) $(LDFLAGS) $(XML2_LIBS) \
	  -o ourfa_client \
	  client.o client_dump.o -L. -lourfa

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

hash.o: hash.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c hash.c
pkt.o: pkt.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c pkt.c
error.o: error.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c error.c
connection.o: connection.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c connection.c
func_call.o: func_call.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c func_call.c
ssl_ctx.o: ssl_ctx.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ssl_ctx.c
xmlapi.o: xmlapi.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c xmlapi.c
client.o: client.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c client.c
client_dump.o: client_dump.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c client_dump.c

