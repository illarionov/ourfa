# New ports collection makefile for:	Ourfa
# Date created:				12 March 2010
# Whom:					Alexey Illarionov <littlesavage@rambler.ru>
#
# $FreeBSD$
#

PORTNAME=	Ourfa
PORTVERSION=	0.2.b1
CATEGORIES=	devel perl5
MASTER_SITES=	${MASTER_SITE_SOURCEFORGE}
MASTER_SITE_SUBDIR=	ourfa
PKGNAMEPREFIX=	p5-
DISTNAME=	ourfa-0.2beta1

MAINTAINER=	littlesavage@orionet.ru
COMMENT=	URFA (UTM Remote Function Access) client library

LIB_DEPENDS=    xml2.5:${PORTSDIR}/textproc/libxml2

PERL_CONFIGURE=	yes
NO_SIZE=        yes
IGNOREFILES=	${DISTFILES}
WRKSRC=		${WRKDIR}/${DISTNAME}/ourfa-perl

MAN3=		Ourfa.3

.include <bsd.port.mk>
