# New ports collection makefile for:	Ourfa
# Date created:				14 December 2010
# Whom:					Alexey Illarionov <littlesavage@rambler.ru>
#
# $FreeBSD$
#

PORTNAME=	ourfa
PORTVERSION=	530002000
CATEGORIES=	devel
MASTER_SITES=	http://github.com/downloads/littlesavage/ourfa/ \
   		http://ls.orionet.ru/

MAINTAINER=	littlesavage@rambler.ru
COMMENT=	URFA (UTM Remote Function Access) client library

LIB_DEPENDS=	xml2.5:${PORTSDIR}/textproc/libxml2

NO_SIZE=	yes
IGNOREFILES=	${DISTFILES}

MAKE_JOBS_SAFE=	yes
PLIST_FILES=	bin/ourfa_client include/ourfa.h lib/libourfa.a

.include <bsd.port.mk>
