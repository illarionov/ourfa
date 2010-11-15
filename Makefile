SHELL=/bin/sh

OURFA_VERSION=\"0.3-beta1\"

CC?=gcc
CFLAGS?= -W -Wall -O2 -DNDEBUG -s
CFLAGS=-W -Wall -g -O0
#CFLAGS+= -DNDEBUG -s

LDFLAGS= -L/usr/local/lib -lssl -lcrypto

XML2_CFLAGS?=	`xml2-config --cflags`
XML2_LIBS?=	`xml2-config --libs`

DESTDIR?=/
PREFIX?=netup/utm5

all: ourfa_client

clean:
	rm -f *.o ourfa_client

ourfa_client: ourfa.h ourfa_hash.c ourfa_xmlapi.c \
	    ourfa_pkt.c ourfa_error.c ourfa_connection.c ourfa_client_dump.c \
	    ourfa_client.c ourfa_func_call.c ourfa_ssl_ctx.c
	$(CC) $(CFLAGS) $(XML2_CFLAGS) $(LDFLAGS) $(XML2_LIBS) \
	-DOURFA_VERSION=${OURFA_VERSION} ourfa_hash.c ourfa_ssl_ctx.c \
	    ourfa_connection.c ourfa_error.c ourfa_pkt.c ourfa_xmlapi.c \
	    ourfa_func_call.c ourfa_client_dump.c ourfa_client.c \
	    -o ourfa_client

install:
	mkdir -p ${DESTDIR}${PREFIX}/bin 2> /dev/null
	cp -p ourfa_client example.sh ${DESTDIR}${PREFIX}/bin
