SHELL=/bin/sh

OURFA_VERSION=\"0.3-beta1\"

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

OBJS= ourfa_hash.o \
      ourfa_xmlapi.o \
      ourfa_pkt.o \
      ourfa_error.o \
      ourfa_connection.o \
      ourfa_func_call.o \
      ourfa_ssl_ctx.o

all: libourfa.a ourfa_client

ourfa_client: ourfa.h libourfa.a ourfa_client.o ourfa_client_dump.o
	$(CC) $(CFLAGS) $(XML2_CFLAGS) $(LDFLAGS) $(XML2_LIBS) \
	  -o ourfa_client \
	  ourfa_client.o ourfa_client_dump.o -L. -lourfa

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

ourfa_hash.o: ourfa_hash.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_hash.c
ourfa_pkt.o: ourfa_pkt.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_pkt.c
ourfa_error.o: ourfa_error.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_error.c
ourfa_connection.o: ourfa_connection.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_connection.c
ourfa_func_call.o: ourfa_func_call.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_func_call.c
ourfa_ssl_ctx.o: ourfa_ssl_ctx.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_ssl_ctx.c
ourfa_xmlapi.o: ourfa_xmlapi.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_xmlapi.c
ourfa_client.o: ourfa_client.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -DOURFA_VERSION=${OURFA_VERSION} -c ourfa_client.c
ourfa_client_dump.o: ourfa_client_dump.c ourfa.h
	$(CC) $(CFLAGS) $(XML2_CFLAGS) -c ourfa_client_dump.c

