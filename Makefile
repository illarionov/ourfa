SHELL=/bin/sh

OURFA_VERSION=\"0.2-beta1\"

CC?=gcc
CFLAGS?= -W -Wall -O2 -DNDEBUG -s
CFLAGS=-W -Wall -g

LDFLAGS= -L/usr/local/lib -lssl

XML2_CFLAGS?=	`xml2-config --cflags`
XML2_LIBS?=	`xml2-config --libs`

DESTDIR?=/
PREFIX?=netup/utm5

all: ourfa_client

clean:
	rm -f *.o ourfa_client

ourfa_client: ourfa_inout.c ourfa_xmlapi.c ourfa_pkt.c ourfa_conn_stream.c ourfa_conn.c ourfa_client_dump.c ourfa_client.c ourfa_xmlapi_resp.c
	$(CC) $(CFLAGS) $(XML2_CFLAGS) $(LDFLAGS) $(XML2_LIBS) \
	-DOURFA_VERSION=${OURFA_VERSION} ourfa_inout.c \
	    ourfa_conn_stream.c ourfa_conn.c ourfa_pkt.c ourfa_xmlapi.c \
	    ourfa_xmlapi_resp.c ourfa_client_dump.c ourfa_client.c \
	    -o ourfa_client

install:
	mkdir -p ${DESTDIR}${PREFIX}/bin 2> /dev/null
	cp -p ourfa_client example.sh ${DESTDIR}${PREFIX}/bin
