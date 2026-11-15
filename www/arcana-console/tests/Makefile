.include "${.CURDIR}/../../../share/mk/arcana.mk"

TESTSDIR=	${TESTSBASE}/arcana/console
ATF_TESTS_C=	pwa_test \
		console_test \
		yaml_test \
		altmark_test

# The page's YANG-CBOR reader, for the pass-through's case.
SRCS.console_test=	console_test.c harness.c ycbor.c
# The permits nacm-sync writes with deny, as the console's build made
# them (nacmallow.h).
CFLAGS.console_test.c+=	-I${.OBJDIR}/..
SRCS.pwa_test=		pwa_test.c harness.c
# The cluster's Raft (craft.c), built WITH_CLUSTER alone: without it the
# cluster's cases skip, and arcana-console:cluster says the build has
# none.
.if ${MK_CLUSTER} != "no"
ATF_TESTS_C+=		raft_test
SRCS.raft_test=		raft_test.c craft.c
CFLAGS.console_test.c+=	-DARCANA_CLUSTER
CFLAGS.pwa_test.c+=	-DARCANA_CLUSTER
.endif
# Alternate marking's loss and RFC 9342's clusters (amclust.c), alone.
SRCS.altmark_test=	altmark_test.c amclust.c
# The panel's YAML, natively: base's libucl and libyaml.
SRCS.yaml_test=		yaml_test.c yaml.c
CFLAGS.yaml_test.c+=	-DDISTDIR='"${.OBJDIR}/../../arcana-ui/dist"'
CFLAGS.yaml.c+=		-I/usr/include/private/yaml
LDADD.yaml_test+=	-lprivateyaml
.PATH:			${.CURDIR}/.. ${.CURDIR}/../../arcana-ui/src

CFLAGS+=	${UCL_CFLAGS} ${SSL_CFLAGS} ${CBLINK_CFLAGS} -DTESTSRC='"${.CURDIR}"'
# pwa_mapgpu: the page's WebGPU backend, built only WITH_WEBGPU.
.if ${MK_WEBGPU} != "no"
CFLAGS.pwa_test.c+=	-DARC_WEBGPU
.endif
LDADD+=		${UCL_LIBS} ${SSL_LDFLAGS} -lcrypto -lm

# No mtree(8) hierarchy outside the tree: create the directory first.
beforeinstall: .PHONY
	${INSTALL} -d -o ${BINOWN} -g ${BINGRP} -m 0755 ${DESTDIR}${TESTSDIR}

.include <bsd.test.mk>
