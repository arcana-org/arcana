PORTNAME=	arcana
DISTVERSIONPREFIX=	v
DISTVERSION=	0.95.0
CATEGORIES=	sysutils www

MAINTAINER=	pouria@FreeBSD.org
COMMENT=	Agent and web console for a fleet of FreeBSD hosts
WWW=		https://github.com/spmzt/arcana

LICENSE=	BSD2CLAUSE
LICENSE_FILE=	${WRKSRC}/LICENSE

BUILD_DEPENDS=	cblink-gen:devel/cblink
LIB_DEPENDS=	libcblink.so:devel/cblink

USES=		uidfix

USE_GITHUB=	yes
GH_ACCOUNT=	spmzt
GH_PROJECT=	arcana
# The submodules, at the commits the tree's are at, which a GitHub
# tarball does not carry: jailconf(8) and libjailconf; libipfeeds and
# libwebpush, linked in; stamp: stampd(8), the STAMP reflector the agent
# runs in the FIBs of its services, built and installed with the rest.
GH_TUPLE=	spmzt:jailconf:19c06d0a74a4d074414c4fd4010f4aa05c6f00c1:jailconf/jailconf \
		spmzt:ipfeeds:c1b04e5362bdb6f7584cb5a54faaddeb744c274e:ipfeeds/ipfeeds \
		spmzt:libwebpush:e23bc37c0ad6d535b5be9ddb36d73e3d816e561c:libwebpush/libwebpush \
		spmzt:stamp:1ac31b181f540915f2fa4e3a47b9fa0994181fe3:stamp/stamp

# stampd gives up root to its own user once bound; the agent builds
# itself as a user nothing else is (arcana-agent(8), BUILDS); not in
# the ports' UIDs and GIDs yet, so in this port's.
USERS=		_stampd _arcanabuild
GROUPS=		_stampd _arcanabuild
UID_FILES=	${PORTSDIR}/UIDs ${FILESDIR}/UIDs
GID_FILES=	${PORTSDIR}/GIDs ${FILESDIR}/GIDs

MAKE_ARGS=	LOCALBASE=${LOCALBASE} \
		PREFIX=${PREFIX} \
		WWWDIR=${WWWDIR}
# The test suite is built only by "make test".
MAKE_ENV=	WITHOUT_DEBUG_FILES=yes \
		WITHOUT_TESTS=yes

OPTIONS_DEFINE=		CLUSTER CONSOLE WEBGPU
OPTIONS_DEFAULT=	CLUSTER CONSOLE
OPTIONS_SUB=		yes

CLUSTER_DESC=	Console cluster replicated by Raft (no effect without CONSOLE)
CONSOLE_DESC=	Web console: its server and the PWA (else only the jail host's programs)
WEBGPU_DESC=	Network map drawn with WebGPU where the browser has it (else WebGL 2)
WEBGPU_IMPLIES=	CONSOLE
# The console's HTTP server is on libwebsockets; the PWA compiles libucl
# and libyaml, the releases base imports, to wasm: their sources, as
# /usr/src has them, fetched here (a package build has no /usr/src).
# libyang for ydescgen, which writes what the console's module
# descriptions take of Arcana's modules at the build.
CONSOLE_BUILD_DEPENDS=	emcc:devel/emscripten \
			libyang3>0:net/libyang3
CONSOLE_LIB_DEPENDS=	libwebsockets.so:net/libwebsockets
CONSOLE_USES=		ssl
CONSOLE_GH_TUPLE=	vstakhov:libucl:0.9.4:libucl/libucl \
			yaml:libyaml:0.2.5:libyaml/libyaml
# arcana-console's libcrypto must be the one libwebsockets uses.
CONSOLE_MAKE_ARGS=	LIBUCL_SRC=${WRKSRC_libucl} \
			LIBYAML_SRC=${WRKSRC_libyaml} \
			SSL_CFLAGS="-I${OPENSSLINC}" \
			SSL_LDFLAGS="-L${OPENSSLLIB}"
CONSOLE_MAKE_ENV_OFF=	WITHOUT_CONSOLE=yes
# The console's cluster: nodes.c and its Raft, craft.c.
CLUSTER_MAKE_ENV_OFF=	WITHOUT_CLUSTER=yes
# The map's WebGPU is emscripten's emdawnwebgpu port, its package taken
# here so that the build fetches nothing.
EMDAWN_V=		v20260423.175430
WEBGPU_MASTER_SITES=	https://github.com/google/dawn/releases/download/${EMDAWN_V}/:dawn
WEBGPU_DISTFILES=	emdawnwebgpu_pkg-${EMDAWN_V}.zip:dawn
WEBGPU_MAKE_ARGS=	EMDAWN=${WRKDIR}/emdawnwebgpu_pkg/emdawnwebgpu.port.py
WEBGPU_MAKE_ENV=	WITH_WEBGPU=yes

SUB_FILES=	pkg-message

# Build everything with the tests and run them with kyua(1) in the build
# tree, as "make check" does.  Cases needing root, or Chromium for the
# PWA, are skipped without them.
do-test:
	cd ${WRKSRC} && ${SETENV} ${MAKE_ENV:NWITHOUT_TESTS=*} ${MAKE_CMD} \
	    ${MAKE_ARGS} check

.include <bsd.port.pre.mk>

# FreeBSD 16.0 and later alone (16-CURRENT among them).
.if ${OSVERSION} < 1600000
IGNORE=		needs FreeBSD 16.0 or later
.endif

.include <bsd.port.post.mk>
