# New ports collection makefile for:	Ourfa
# Date created:				12 March 2010
# Whom:					Alexey Illarionov <littlesavage@rambler.ru>
#
# $FreeBSD$
#

PORTNAME=	Ourfa
PORTVERSION=	521008.0.0
CATEGORIES=	devel perl5
MASTER_SITES=	${MASTER_SITE_SOURCEFORGE}
MASTER_SITE_SUBDIR=	ourfa
PKGNAMEPREFIX=	p5-
DISTNAME=	Ourfa-521008.0.0_01

MAINTAINER=	littlesavage@rambler.ru
COMMENT=	Perl bindings for URFA (UTM Remote Function Access)

LIB_DEPENDS=    xml2.5:${PORTSDIR}/textproc/libxml2
BUILD_DEPENDS=	${LOCALBASE}/lib/libourfa.a

PERL_CONFIGURE=	yes
NO_SIZE=        yes
IGNOREFILES=	${DISTFILES}

MAKE_JOBS_SAFE=	yes

MAN3=		Ourfa.3

.include <bsd.port.mk>
