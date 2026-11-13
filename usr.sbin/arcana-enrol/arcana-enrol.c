/*-
 * SPDX-License-Identifier: BSD-2-Clause
 *
 * Copyright (c) 2026 Pouria Mousavizadeh Tehrani <pouria@FreeBSD.org>
 */

/*
 * arcana-enrol: join this host to a arcana console.  Makes a key and
 * a certificate request, sends it with the one-time token the console
 * gave, and writes the certificate and the CA where arcana-agent(8) reads
 * them; with -s, enables and starts arcana-agent with them.  The CA that
 * comes back is the agent's trust anchor: each of its certificates must
 * be one whose SHA-256 the token carries (the console's "arce1_" token:
 * base64url of its secret and the roots' SHA-256s) or -f names; a token
 * that carries none, and no -f, enrols only with -i, and over plain
 * HTTP only with -i too.
 */

#include <sys/param.h>
#include <sys/capsicum.h>
#include <sys/stat.h>
#include <sys/wait.h>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

#include <capsicum_helpers.h>
#include <ctype.h>
#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <fetch.h>
#include <spawn.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ucl.h>
#include <unistd.h>

#ifndef PREFIX
#define	PREFIX		"/usr/local"
#endif
#define	PATH_ETC	PREFIX "/etc/arcana"
#define	DEFAULT_PORT	4310
#define	MAX_REPLY	(256 * 1024)
#define	MAX_PINS	8
#define	TOKEN_PREFIX	"arce1_"
#define	TOKEN_PINS	4	/* the console's at most */

extern char	**environ;

static void	 usage(void) __dead2;
static const char *ssl_err(void);
static char	*csr_pem(EVP_PKEY *, const char *);
static char	*post(const char *, const char *, bool);
static bool	 pin_parse(const char *, unsigned char *);
static void	 token_pins(const char *, unsigned char (*)[32], size_t *,
		    size_t);
static void	 pins_check(const char *, unsigned char (*)[32], size_t);
static void	 write_file(int, const char *, const char *, mode_t);
static void	 write_key(int, const char *, EVP_PKEY *);
static bool	 run(char *const []);

static void
usage(void)
{

	fprintf(stderr, "usage: arcana-enrol [-is] [-a address ...] "
	    "[-f sha256 ...] [-p port]\n"
	    "                     [-d directory] [-n name] console-url "
	    "token\n");
	exit(2);
}

static const char *
ssl_err(void)
{
	const char	*s;

	s = ERR_reason_error_string(ERR_get_error());
	return (s != NULL ? s : "libcrypto error");
}

/* A certificate request for key, CN=name, as PEM. */
static char *
csr_pem(EVP_PKEY *key, const char *name)
{
	X509_REQ	*req;
	BIO		*b;
	char		*s, *out;
	long		 len;

	out = NULL;
	if ((req = X509_REQ_new()) == NULL || (b = BIO_new(BIO_s_mem())) ==
	    NULL)
		errx(1, "certificate request: %s", ssl_err());
	if (X509_NAME_add_entry_by_txt(X509_REQ_get_subject_name(req), "CN",
	    MBSTRING_UTF8, (const unsigned char *)name, -1, -1, 0) != 1 ||
	    X509_REQ_set_pubkey(req, key) != 1 ||
	    X509_REQ_sign(req, key, EVP_sha256()) <= 0 ||
	    PEM_write_bio_X509_REQ(b, req) != 1 ||
	    (len = BIO_get_mem_data(b, &s)) <= 0 ||
	    (out = malloc((size_t)len + 1)) == NULL)
		errx(1, "certificate request: %s", ssl_err());
	memcpy(out, s, (size_t)len);
	out[len] = '\0';
	BIO_free(b);
	X509_REQ_free(req);
	return (out);
}

/*
 * POST body as JSON to url; the reply's body, or an error exit.  Plain
 * HTTP only when insecure: what comes back is the agent's trust anchor.
 */
static char *
post(const char *url, const char *body, bool insecure)
{
	struct url	*u;
	FILE		*fp;
	char		*buf;
	size_t		 len, n;

	if ((u = fetchParseURL(url)) == NULL)
		errx(1, "%s: %s", url, fetchLastErrString);
	if (strcmp(u->scheme, "https") != 0 && strcmp(u->scheme, "http") != 0)
		errx(1, "%s: not an http(s) URL", url);
	if (strcmp(u->scheme, "http") == 0 && !insecure)
		errx(1, "%s: not HTTPS: the token and the CA the agent is to "
		    "trust would travel in the clear; -i to enrol over plain "
		    "HTTP all the same (the CA is checked by the token's pins)",
		    url);
	if (strcmp(u->scheme, "http") == 0)
		warnx("%s: not HTTPS; the token and the certificate travel in "
		    "the clear", url);
	if ((fp = fetchReqHTTP(u, "POST", "", "application/json", body)) ==
	    NULL)
		errx(1, "%s: %s", url, fetchLastErrString);
	if ((buf = malloc(MAX_REPLY)) == NULL)
		err(1, "malloc");
	for (len = 0; len < MAX_REPLY - 1; len += n)
		if ((n = fread(buf + len, 1, MAX_REPLY - 1 - len, fp)) == 0)
			break;
	buf[len] = '\0';
	fclose(fp);
	fetchFreeURL(u);
	return (buf);
}

/* A SHA-256 fingerprint as openssl(1) or the console shows it, colons
 * or none, either case, into its 32 bytes. */
static bool
pin_parse(const char *s, unsigned char *out)
{
	size_t	n;

	for (n = 0; n < 32; n++) {
		if (n > 0 && *s == ':')
			s++;
		if (!isxdigit((unsigned char)s[0]) ||
		    !isxdigit((unsigned char)s[1]))
			return (false);
		out[n] = (unsigned char)(digittoint((unsigned char)s[0]) << 4 |
		    digittoint((unsigned char)s[1]));
		s += 2;
	}
	return (*s == '\0');
}

/*
 * The roots' SHA-256s the console's token carries, after its 32 bytes
 * of secret, added to pins (*np of them, max at most); exits on a token
 * that is not one.
 */
static void
token_pins(const char *token, unsigned char (*pins)[32], size_t *np,
    size_t max)
{
	unsigned char	 raw[32 * (1 + TOKEN_PINS) + 3];
	BIO		*b, *b64;
	size_t		 n, i;
	char		*s, *p;
	int		 r;

	if (strncmp(token, TOKEN_PREFIX, sizeof(TOKEN_PREFIX) - 1) != 0)
		errx(1, "not a token of the console's (%s...)", TOKEN_PREFIX);
	/* base64url to base64, padded, for libcrypto. */
	n = strlen(token + sizeof(TOKEN_PREFIX) - 1);
	if (n == 0 || n > 4 * sizeof(raw) / 3 || (s = calloc(1, n + 4)) == NULL)
		errx(1, "not a token of the console's");
	memcpy(s, token + sizeof(TOKEN_PREFIX) - 1, n);
	for (p = s; *p != '\0'; p++)
		if (*p == '-')
			*p = '+';
		else if (*p == '_')
			*p = '/';
		else if (!isalnum((unsigned char)*p))
			errx(1, "not a token of the console's");
	while (n % 4 != 0)
		s[n++] = '=';
	if ((b = BIO_new_mem_buf(s, (int)n)) == NULL ||
	    (b64 = BIO_new(BIO_f_base64())) == NULL)
		errx(1, "the token: %s", ssl_err());
	BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
	b = BIO_push(b64, b);
	r = BIO_read(b, raw, sizeof(raw));
	BIO_free_all(b);
	free(s);
	if (r < 32 || (r - 32) % 32 != 0 || r > 32 * (1 + TOKEN_PINS))
		errx(1, "not a token of the console's");
	for (i = 32; i < (size_t)r; i += 32) {
		if (*np == max)
			errx(1, "at most %zu fingerprints", max);
		memcpy(pins[(*np)++], raw + i, 32);
	}
	explicit_bzero(raw, sizeof(raw));
}

/*
 * Each certificate of the CA the console sent one of the pinned: one
 * that is not, or none at all, and nothing is written.
 */
static void
pins_check(const char *ca, unsigned char (*pins)[32], size_t npins)
{
	unsigned char	 md[EVP_MAX_MD_SIZE];
	unsigned int	 mdlen;
	BIO		*b;
	X509		*x;
	size_t		 i, n;

	if (npins == 0)
		return;
	if ((b = BIO_new_mem_buf(ca, -1)) == NULL)
		errx(1, "the console's CA: %s", ssl_err());
	for (n = 0; (x = PEM_read_bio_X509(b, NULL, NULL, NULL)) != NULL; n++) {
		if (X509_digest(x, EVP_sha256(), md, &mdlen) != 1 ||
		    mdlen != 32)
			errx(1, "the console's CA: %s", ssl_err());
		X509_free(x);
		for (i = 0; i < npins && memcmp(pins[i], md, 32) != 0; i++)
			;
		if (i == npins)
			errx(1, "the CA the console sent is not the one the token "
			    "or -f pins (its certificate %zu): nothing written",
			    n + 1);
	}
	BIO_free(b);
	if (n == 0)
		errx(1, "the console sent no CA certificate: nothing written");
}

/*
 * The files are written in the directory dfd is open on, by name:
 * what a process in capability mode (capsicum(4)) can still do.
 */
static void
write_file(int dfd, const char *name, const char *text, mode_t mode)
{
	char	tmp[NAME_MAX + 1];
	int	fd;
	size_t	len, off;
	ssize_t	w;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", name);
	if ((fd = mkostempsat(dfd, tmp, 0, O_CLOEXEC)) == -1)
		err(1, "%s", tmp);
	len = strlen(text);
	for (off = 0; off < len; off += (size_t)w)
		if ((w = write(fd, text + off, len - off)) <= 0) {
			(void)unlinkat(dfd, tmp, 0);
			err(1, "write %s", tmp);
		}
	if (fchmod(fd, mode) == -1 || fsync(fd) == -1 || close(fd) == -1 ||
	    renameat(dfd, tmp, dfd, name) == -1) {
		(void)unlinkat(dfd, tmp, 0);
		err(1, "%s", name);
	}
}

static void
write_key(int dfd, const char *name, EVP_PKEY *key)
{
	char	tmp[NAME_MAX + 1];
	FILE	*fp;
	int	fd;

	snprintf(tmp, sizeof(tmp), "%s.XXXXXX", name);
	if ((fd = mkostempsat(dfd, tmp, 0, O_CLOEXEC)) == -1 ||
	    fchmod(fd, 0600) == -1 || (fp = fdopen(fd, "w")) == NULL)
		err(1, "%s", tmp);
	if (PEM_write_PrivateKey(fp, key, NULL, NULL, 0, NULL, NULL) != 1) {
		(void)unlinkat(dfd, tmp, 0);
		errx(1, "%s: %s", tmp, ssl_err());
	}
	if (fflush(fp) != 0 || fsync(fd) == -1 || fclose(fp) != 0 ||
	    renameat(dfd, tmp, dfd, name) == -1) {
		(void)unlinkat(dfd, tmp, 0);
		err(1, "%s", name);
	}
}

/* Run a program; true if it exited 0. */
static bool
run(char *const argv[])
{
	pid_t	pid;
	int	status;

	if (posix_spawnp(&pid, argv[0], NULL, NULL, argv, environ) != 0) {
		warn("%s", argv[0]);
		return (false);
	}
	while (waitpid(pid, &status, 0) == -1)
		if (errno != EINTR)
			return (false);
	return (WIFEXITED(status) && WEXITSTATUS(status) == 0);
}

/*
 * The one who runs sysrc and service at the end: a child forked before
 * capability mode, which cannot run programs.  It waits for a 'g' on
 * the pipe, written once the files are in place; anything else, or the
 * pipe's end, and it does nothing.
 */
static pid_t
runner_fork(char *const sysrc[], char *const service[], const char *flags,
    int *gofd)
{
	pid_t	pid;
	char	c;
	int	p[2];

	if (pipe2(p, O_CLOEXEC) == -1)
		err(1, "pipe");
	if ((pid = fork()) == -1)
		err(1, "fork");
	if (pid == 0) {
		close(p[1]);
		if (read(p[0], &c, 1) != 1 || c != 'g')
			_exit(1);
		if (!run(sysrc))
			errx(1, "sysrc failed; set arcana_agent_listen=\"%s\" "
			    "by hand", flags);
		if (!run(service))
			errx(1, "service arcana_agent restart failed");
		_exit(0);
	}
	close(p[0]);
	*gofd = p[1];
	return (pid);
}

int
main(int argc, char *argv[])
{
	struct ucl_parser	*p;
	ucl_object_t		*o, *body;
	const ucl_object_t	*v;
	EVP_PKEY		*key;
	const char		*dir, *name, *url, *token, *cert, *ca;
	const char		*addrs[8];
	size_t			 naddrs, i;
	const char		*host;
	char			*e;
	char			 hostname[MAXHOSTNAMELEN], api[1024], *csr;
	char			 capath[MAXPATHLEN], certpath[MAXPATHLEN];
	char			 keypath[MAXPATHLEN], flags[1024], *reply;
	char			 listen[256];
	char			*sysrc[8], *service[4];
	const char		*quote;
	int			 ns, dfd, gofd, status;
	pid_t			 runner;
	unsigned char		*json;
	unsigned char		 pins[MAX_PINS][32];
	size_t			 npins;
	long			 port;
	bool			 start, insecure;
	int			 ch;

	dir = PATH_ETC;
	naddrs = npins = 0;
	name = NULL;
	port = DEFAULT_PORT;
	start = insecure = false;
	while ((ch = getopt(argc, argv, "a:d:f:in:p:s")) != -1) {
		switch (ch) {
		case 'a':
			if (naddrs == nitems(addrs))
				errx(1, "at most %zu addresses", nitems(addrs));
			addrs[naddrs++] = optarg;
			break;
		case 'd':
			dir = optarg;
			break;
		case 'f':
			if (npins == MAX_PINS)
				errx(1, "at most %d fingerprints", MAX_PINS);
			if (!pin_parse(optarg, pins[npins++]))
				errx(1, "%s: not a SHA-256 fingerprint", optarg);
			break;
		case 'i':
			insecure = true;
			break;
		case 'n':
			name = optarg;
			break;
		case 'p':
			port = strtol(optarg, &e, 10);
			if (*optarg == '\0' || *e != '\0' || port < 1 ||
			    port > 65535)
				errx(1, "%s: not a port", optarg);
			break;
		case 's':
			start = true;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;
	if (argc != 2)
		usage();
	url = argv[0];
	token = argv[1];
	token_pins(token, pins, &npins, MAX_PINS);
	/* Nothing to check the CA by: the agent would trust whatever came. */
	if (npins == 0 && !insecure)
		errx(1, "the token pins no CA, and no -f does: -i to trust the "
		    "CA the console sends as it comes");
	if (name == NULL) {
		if (gethostname(hostname, sizeof(hostname)) == -1)
			err(1, "gethostname");
		name = hostname;
	}
	snprintf(api, sizeof(api), "%.*s/api/enrol", (int)strcspn(url, "/") ==
	    (int)strlen(url) || url[strlen(url) - 1] != '/' ?
	    (int)strlen(url) : (int)strlen(url) - 1, url);
	snprintf(capath, sizeof(capath), "%s/ca.pem", dir);
	snprintf(certpath, sizeof(certpath), "%s/host.pem", dir);
	snprintf(keypath, sizeof(keypath), "%s/host.key", dir);
	if (mkdir(dir, 0755) == -1 && errno != EEXIST)
		err(1, "mkdir %s", dir);
	if ((dfd = open(dir, O_RDONLY | O_DIRECTORY | O_CLOEXEC)) == -1)
		err(1, "%s", dir);

	/* Every address family by default: v6only is on in FreeBSD. */
	if (naddrs == 0) {
		addrs[naddrs++] = "0.0.0.0";
		addrs[naddrs++] = "::";
	}
	/* The local socket is the service's own; these are the rest. */
	flags[0] = '\0';
	for (i = 0; i < naddrs; i++) {
		snprintf(listen, sizeof(listen), "%stcp://%s%s%s:%ld",
		    i > 0 ? " " : "", strchr(addrs[i], ':') != NULL ? "[" : "",
		    addrs[i], strchr(addrs[i], ':') != NULL ? "]" : "", port);
		strlcat(flags, listen, sizeof(flags));
	}
	/* The files are named only where the service would not look. */
	ns = 0;
	if ((sysrc[ns++] = strdup("sysrc")) == NULL ||
	    (sysrc[ns++] = strdup("arcana_agent_enable=YES")) == NULL ||
	    asprintf(&sysrc[ns++], "arcana_agent_listen=%s", flags) == -1)
		err(1, "asprintf");
	if (strcmp(dir, PATH_ETC) != 0 && (
	    asprintf(&sysrc[ns++], "arcana_agent_ca=%s", capath) == -1 ||
	    asprintf(&sysrc[ns++], "arcana_agent_cert=%s", certpath) == -1 ||
	    asprintf(&sysrc[ns++], "arcana_agent_key=%s", keypath) == -1))
		err(1, "asprintf");
	sysrc[ns] = NULL;
	service[0] = (char *)(uintptr_t)"service";
	service[1] = (char *)(uintptr_t)"arcana_agent";
	service[2] = (char *)(uintptr_t)"restart";
	service[3] = NULL;
	runner = -1;
	gofd = -1;
	if (start)
		runner = runner_fork(sysrc, service, flags, &gofd);

	if ((key = EVP_PKEY_Q_keygen(NULL, NULL, "EC", "P-256")) == NULL)
		errx(1, "key: %s", ssl_err());
	csr = csr_pem(key, name);
	body = ucl_object_typed_new(UCL_OBJECT);
	ucl_object_insert_key(body, ucl_object_fromstring(token), "token", 0,
	    false);
	ucl_object_insert_key(body, ucl_object_fromstring(csr), "csr", 0,
	    false);
	if ((json = ucl_object_emit(body, UCL_EMIT_JSON_COMPACT)) == NULL)
		errx(1, "cannot build the request");
	ucl_object_unref(body);
	free(csr);

	reply = post(api, (const char *)json, insecure);
	free(json);
	/*
	 * Capability mode from here (capsicum(4)): the console has
	 * answered; its answer is parsed and the files written through
	 * the directory open above, and nothing else is reachable.
	 */
	caph_cache_catpages();
	if (caph_enter() == -1)
		err(1, "cap_enter");
	p = ucl_parser_new(UCL_PARSER_NO_IMPLICIT_ARRAYS |
	    UCL_PARSER_DISABLE_MACRO | UCL_PARSER_NO_TIME);
	o = NULL;
	if (ucl_parser_add_string(p, reply, 0))
		o = ucl_parser_get_object(p);
	ucl_parser_free(p);
	if (o == NULL)
		errx(1, "the console did not answer with JSON: %.200s", reply);
	if ((v = ucl_object_lookup_path(o, "error.message")) != NULL)
		errx(1, "the console refused: %s", ucl_object_tostring(v));
	cert = (v = ucl_object_lookup(o, "certificate")) != NULL ?
	    ucl_object_tostring(v) : NULL;
	ca = (v = ucl_object_lookup(o, "ca")) != NULL ?
	    ucl_object_tostring(v) : NULL;
	host = (v = ucl_object_lookup(o, "host")) != NULL ?
	    ucl_object_tostring(v) : name;
	if (cert == NULL || ca == NULL)
		errx(1, "the console's answer has no certificate: %.200s",
		    reply);
	pins_check(ca, pins, npins);

	write_key(dfd, "host.key", key);
	write_file(dfd, "host.pem", cert, 0644);
	write_file(dfd, "ca.pem", ca, 0644);
	close(dfd);
	EVP_PKEY_free(key);
	printf("enrolled as %s; certificate in %s, key in %s, CA in %s\n", host,
	    certpath, keypath, capath);
	if (!start) {
		printf("to run arcana-agent with them:\n ");
		for (i = 0; i < (size_t)ns; i++) {
			quote = strchr(sysrc[i], ' ') != NULL ? "'" : "";
			printf(" %s%s%s", quote, sysrc[i], quote);
		}
		printf("\n  service arcana_agent restart\n");
		ucl_object_unref(o);
		free(reply);
		return (0);
	}
	/* The runner, forked before capability mode, does the rest. */
	if (write(gofd, "g", 1) != 1)
		err(1, "the runner is gone");
	close(gofd);
	while (waitpid(runner, &status, 0) == -1)
		if (errno != EINTR)
			err(1, "waitpid");
	if (!WIFEXITED(status) || WEXITSTATUS(status) != 0)
		return (1);
	printf("arcana-agent is enabled and running on port %ld\n", port);
	for (i = 0; i < (size_t)ns; i++)
		free(sysrc[i]);
	ucl_object_unref(o);
	free(reply);
	return (0);
}
