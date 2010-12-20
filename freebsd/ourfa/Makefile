# New ports collection makefile for:	Ourfa
# Date created:				14 December 2010
# Whom:					Alexey Illarionov <littlesavage@rambler.ru>
#
# $FreeBSD$
#

PORTNAME=	ourfa
PORTVERSION=	521008001
CATEGORIES=	devel
MASTER_SITES=	${MASTER_SITE_SOURCEFORGE}
MASTER_SITE_SUBDIR=	ourfa

MAINTAINER=	littlesavage@rambler.ru
COMMENT=	URFA (UTM Remote Function Access) client library

LIB_DEPENDS=	xml2.5:${PORTSDIR}/textproc/libxml2

NO_SIZE=	yes
IGNOREFILES=	${DISTFILES}

MAKE_JOBS_SAFE=	yes
PLIST_FILES=	bin/ourfa_client include/ourfa.h lib/libourfa.a

.include <bsd.port.mk>
