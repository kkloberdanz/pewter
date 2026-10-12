/*
 * pewter - a minimal, chrooted, fork-per-connection static HTTP server.
 *
 * Design in one paragraph: the parent binds the listening socket as root,
 * chroots into the document root, drops to an unprivileged uid/gid, verifies
 * the drop, and only then starts accepting connections.  Every connection is
 * handled by a forked child that serves exactly one GET or HEAD request and
 * exits.  All request handling happens in fixed-size stack buffers; no user
 * input is ever echoed back in a response.  Files are sent with the
 * platform's sendfile(2) when available, else with a read/write loop.
 *
 * Built with -DPEWTER_TLS the same binary can serve HTTPS: the parent
 * loads the certificate and key before chroot, and each child runs the
 * handshake and then speaks HTTP through the TLS session.
 *
 * Strict C89 (-std=c89 -pedantic-errors).  Dependencies: libc only, plus
 * OpenSSL or LibreSSL for the optional TLS build.
 */

#if defined(__linux__)
#  define _GNU_SOURCE 1        /* under -std=c89 glibc/musl hide everything
                                  beyond ANSI C without this: POSIX.1-2008,
                                  sendfile(2), setgroups(2), chroot(2) ... */
#  define _FILE_OFFSET_BITS 64
#elif defined(__APPLE__)
#  define _DARWIN_C_SOURCE 1   /* un-hides sendfile(2), setgroups(2), chroot(2) */
#endif
/* FreeBSD: define nothing.  Its <sys/cdefs.h> exposes everything by default
   and defining _POSIX_C_SOURCE would *hide* the BSD symbols we need. */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <pwd.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#if defined(__linux__)
#  include <sys/sendfile.h>
#  include <sys/prctl.h>
#endif

#if defined(__FreeBSD__)
#  include <sys/capsicum.h>
#  include <sys/procctl.h>
#endif

#if defined(PEWTER_TLS)
#  include <openssl/ssl.h>
#  include <openssl/err.h>
#  include <openssl/rand.h>
#endif

#if defined(__GNUC__)
#  define PRINTF_LIKE(f, a) __attribute__((format(printf, f, a)))
#  define NORETURN          __attribute__((noreturn))
#  define EXTENSION         __extension__  /* exempt one expression from
                                              -pedantic, e.g. a system
                                              macro using long long */
#else
#  define PRINTF_LIKE(f, a)
#  define NORETURN
#  define EXTENSION
#endif

#ifndef O_CLOEXEC
#  define O_CLOEXEC 0
#endif

#ifndef O_DIRECTORY
#  define O_DIRECTORY 0
#endif

#ifndef PATH_MAX
#  define PATH_MAX 4096
#endif

#if !defined(PEWTER_NO_SENDFILE) && \
    (defined(__linux__) || defined(__APPLE__) || defined(__FreeBSD__))
#  define PEWTER_HAVE_SENDFILE 1
#endif

/* Linux children run under a seccomp syscall allowlist, on the
   architectures the filter is written for.  Sanitizer builds define
   PEWTER_NO_SECCOMP: their runtimes make system calls of their own, and a
   killed child would hide the report the build exists to produce. */
#if defined(__linux__) && !defined(PEWTER_NO_SECCOMP) && \
    (defined(__x86_64__) || defined(__aarch64__))
#  define PEWTER_HAVE_SECCOMP 1
#  include <stddef.h>
#  include <sys/mman.h>
#  include <sys/syscall.h>
#  include <linux/audit.h>
#  include <linux/filter.h>
#  include <linux/seccomp.h>
#  ifndef SECCOMP_RET_KILL_PROCESS
#    define SECCOMP_RET_KILL_PROCESS 0x80000000U   /* Linux 4.14 */
#  endif
#endif

/* ------------------------------------------------------------------ */
/* Configuration                                                       */
/* ------------------------------------------------------------------ */

#define SERVER_NAME          "pewter"
#define DEFAULT_ADDR         "0.0.0.0"
#define DEFAULT_PORT         "8080"
#define DEFAULT_USER         "nobody"
#define DEFAULT_TIMEOUT      30
#define DEFAULT_MAX_CHILDREN 64
#define LISTEN_BACKLOG       128

#define REQ_BUF_SIZE   8192          /* whole request head must fit here   */
#define MAX_PATH_LEN   4096          /* decoded request path               */
#define ENC_PATH_LEN   (MAX_PATH_LEN * 3 + 8)  /* re-encoded for Location  */
#define HDR_BUF_SIZE   (ENC_PATH_LEN + 512)    /* response head            */
#define COPY_BUF_SIZE  65536         /* read/write fallback chunk          */
#define LOG_TARGET_LEN 256           /* request target as logged           */
#define LOG_METHOD_LEN 32            /* request method as logged           */
#define LOG_LINE_LEN   (PATH_MAX + 512) /* one log line, emitted whole     */
#define CHILD_MAX_FDS  16            /* RLIMIT_NOFILE in each child        */

static volatile sig_atomic_t g_active_children = 0;
static volatile sig_atomic_t g_quit = 0;
static int g_timeout = DEFAULT_TIMEOUT;
static int g_rootfd = -1;       /* the chroot's "/"; children open through it */

/* A client connection: the socket, plus the TLS session when HTTPS is on.
   All request and response I/O goes through conn_read/conn_write_all so
   the HTTP code never knows which of the two it is talking to. */
struct conn {
    int fd;
#if defined(PEWTER_TLS)
    SSL *ssl;                   /* NULL on a plain-text connection */
#endif
};

#if defined(PEWTER_TLS)
static SSL_CTX *g_tls = NULL;   /* NULL unless -C/-K were given */

/* TLS 1.2 suites: ECDHE only (forward secrecy), AEAD only.  TLS 1.3 has
   its own fixed list of AEAD suites and is not affected by this. */
#define TLS_CIPHERS "ECDHE+AESGCM:ECDHE+CHACHA20:!aNULL:!eNULL"

/* Context options that not every library version has.  Resolved here
   rather than with #ifdef inside the SSL_CTX_set_options() call, which
   is a macro in LibreSSL and must not contain directives. */
#ifdef SSL_OP_NO_RENEGOTIATION
#  define TLS_OPT_NO_RENEGOTIATION SSL_OP_NO_RENEGOTIATION
#else
#  define TLS_OPT_NO_RENEGOTIATION 0
#endif
#ifdef SSL_OP_IGNORE_UNEXPECTED_EOF
#  define TLS_OPT_IGNORE_UNEXPECTED_EOF SSL_OP_IGNORE_UNEXPECTED_EOF
#else
#  define TLS_OPT_IGNORE_UNEXPECTED_EOF 0
#endif
#endif

/* ------------------------------------------------------------------ */
/* Logging                                                             */
/* ------------------------------------------------------------------ */

static void vlogmsg(const char *fmt, va_list ap) PRINTF_LIKE(1, 0);
static void logmsg(const char *fmt, ...) PRINTF_LIKE(1, 2);
static void fatal(const char *fmt, ...) PRINTF_LIKE(1, 2) NORETURN;
static int write_all(int fd, const char *buf, size_t len);

/* Length of a line after snprintf returned `n` for the space following its
   first `len` bytes, with `cap` bytes available in all: truncated output
   counts only what fit, a formatting error adds nothing. */
static size_t log_append(size_t len, int n, size_t cap)
{
    if (n < 0)
        return len;
    return (size_t)n < cap - len ? len + (size_t)n : cap - 1;
}

/* Every child logs to the same stderr.  A line is assembled in full and
   emitted with one write(2), so lines from concurrent children cannot
   interleave on a shared pipe; one that does not fit is truncated. */
static void vlogmsg(const char *fmt, va_list ap)
{
    char line[LOG_LINE_LEN];
    size_t cap = sizeof line - 1;             /* room for the newline */
    size_t len;
    time_t now;
    struct tm *tm;

    now = time(NULL);
    tm = gmtime(&now);
    len = tm != NULL ? strftime(line, cap, "%Y-%m-%dT%H:%M:%SZ", tm) : 0;
    if (len == 0) {
        line[0] = '-';
        len = 1;
    }
    len = log_append(len, snprintf(line + len, cap - len, " [%ld] ",
                                   (long)getpid()), cap);
    len = log_append(len, vsnprintf(line + len, cap - len, fmt, ap), cap);
    line[len++] = '\n';
    (void)write_all(STDERR_FILENO, line, len);
}

static void logmsg(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlogmsg(fmt, ap);
    va_end(ap);
}

static void fatal(const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    vlogmsg(fmt, ap);
    va_end(ap);
    exit(1);
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

static int write_all(int fd, const char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        buf += n;
        len -= (size_t)n;
    }
    return 0;
}

/* ------------------------------------------------------------------ */
/* Connection I/O: plain socket or TLS session                         */
/* ------------------------------------------------------------------ */

#if defined(PEWTER_TLS)
/* Map a failed SSL_read/SSL_write onto recv/write conventions: 0 for end
   of stream (with or without close_notify), -1 with errno set otherwise.
   EINTR and EAGAIN from the socket pass through so callers retry or time
   out exactly as they would on a plain connection. */
static ssize_t tls_result(SSL *ssl, int n)
{
    switch (SSL_get_error(ssl, n)) {
    case SSL_ERROR_ZERO_RETURN:
        return 0;
    case SSL_ERROR_SYSCALL:
        if (n == 0 || errno == 0)
            return 0;              /* peer closed without close_notify */
        return -1;
    case SSL_ERROR_WANT_READ:
    case SSL_ERROR_WANT_WRITE:
        errno = EAGAIN;            /* blocking socket: SO_RCVTIMEO/SO_SNDTIMEO */
        return -1;
    default:
        errno = EPROTO;
        return -1;
    }
}
#endif

static ssize_t conn_read(struct conn *c, char *buf, size_t len)
{
#if defined(PEWTER_TLS)
    if (c->ssl != NULL) {
        int n;
        if (len > (size_t)INT_MAX)
            len = (size_t)INT_MAX;
        n = SSL_read(c->ssl, buf, (int)len);
        return n > 0 ? (ssize_t)n : tls_result(c->ssl, n);
    }
#endif
    return recv(c->fd, buf, len, 0);
}

static int conn_write_all(struct conn *c, const char *buf, size_t len)
{
#if defined(PEWTER_TLS)
    if (c->ssl != NULL) {
        while (len > 0) {
            int want = len > (size_t)INT_MAX ? INT_MAX : (int)len;
            int n = SSL_write(c->ssl, buf, want);
            if (n <= 0) {
                if (tls_result(c->ssl, n) == 0)
                    errno = EPIPE;
                if (errno == EINTR)
                    continue;      /* same buffer and length: allowed */
                return -1;
            }
            buf += n;
            len -= (size_t)n;
        }
        return 0;
    }
#endif
    return write_all(c->fd, buf, len);
}

static void http_date(time_t t, char *buf, size_t sz)
{
    struct tm *tm = gmtime(&t);
    if (tm == NULL || strftime(buf, sz, "%a, %d %b %Y %H:%M:%S GMT", tm) == 0)
        buf[0] = '\0';
}

static const char *status_reason(int code)
{
    switch (code) {
    case 200: return "OK";
    case 301: return "Moved Permanently";
    case 400: return "Bad Request";
    case 403: return "Forbidden";
    case 404: return "Not Found";
    case 405: return "Method Not Allowed";
    case 408: return "Request Timeout";
    case 413: return "Content Too Large";
    case 414: return "URI Too Long";
    case 431: return "Request Header Fields Too Large";
    case 500: return "Internal Server Error";
    case 501: return "Not Implemented";
    case 503: return "Service Unavailable";
    case 505: return "HTTP Version Not Supported";
    default:  return "Unknown";
    }
}

/* Copy `in` to `out`, replacing anything that is not printable ASCII so a
   hostile request line cannot inject control characters into the log. */
static void log_safe(const char *in, char *out, size_t outsz)
{
    size_t i;
    for (i = 0; i + 1 < outsz && in[i] != '\0'; i++) {
        unsigned char c = (unsigned char)in[i];
        out[i] = (char)((c < 0x20 || c >= 0x7f) ? '?' : c);
    }
    out[i] = '\0';
}

static void client_ip(const struct sockaddr_storage *ss, char *buf, size_t sz)
{
    const void *src;

    buf[0] = '?';
    buf[1] = '\0';
    if (ss->ss_family == AF_INET)
        src = &((const struct sockaddr_in *)ss)->sin_addr;
    else if (ss->ss_family == AF_INET6)
        src = &((const struct sockaddr_in6 *)ss)->sin6_addr;
    else
        return;
    if (inet_ntop(ss->ss_family, src, buf, (socklen_t)sz) == NULL) {
        buf[0] = '?';
        buf[1] = '\0';
    }
}

static int parse_int(const char *s, long lo, long hi, const char *what)
{
    char *end;
    long v;

    errno = 0;
    v = strtol(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || v < lo || v > hi)
        fatal("invalid %s: '%s' (expected %ld..%ld)", what, s, lo, hi);
    return (int)v;
}

/* ------------------------------------------------------------------ */
/* Response head                                                       */
/* ------------------------------------------------------------------ */

/* Write the status line and headers.  `mtime` of 0 omits Last-Modified;
   `extra` is an optional, already CRLF-terminated header line. */
static int send_head(struct conn *c, int code, const char *ctype, off_t clen,
                     time_t mtime, const char *extra)
{
    char hdr[HDR_BUF_SIZE];
    char date[64];
    char lm[64];
    char lmline[96];
    int n;
    time_t now;

    now = time(NULL);
    http_date(now, date, sizeof date);
    lmline[0] = '\0';
    if (mtime != 0) {
        http_date(mtime, lm, sizeof lm);
        n = snprintf(lmline, sizeof lmline, "Last-Modified: %s\r\n", lm);
        if (n < 0 || (size_t)n >= sizeof lmline)
            lmline[0] = '\0';
    }
    n = snprintf(hdr, sizeof hdr,
                 "HTTP/1.1 %d %s\r\n"
                 "Date: %s\r\n"
                 "Server: " SERVER_NAME "\r\n"
                 "Content-Type: %s\r\n"
                 "Content-Length: %lu\r\n"
                 "%s%s"
                 "X-Content-Type-Options: nosniff\r\n"
                 "Connection: close\r\n"
                 "\r\n",
                 code, status_reason(code), date, ctype,
                 (unsigned long)clen, lmline, extra != NULL ? extra : "");
    if (n < 0 || (size_t)n >= sizeof hdr)
        return -1;
    return conn_write_all(c, hdr, (size_t)n);
}

/* Error responses carry a tiny fixed text/plain body ("404 Not Found\n").
   Nothing from the request is reflected, so there is no injection surface. */
static void send_error(struct conn *c, int code, int is_head, const char *extra)
{
    char body[128];
    int n;

    n = snprintf(body, sizeof body, "%d %s\n", code, status_reason(code));
    if (n < 0 || (size_t)n >= sizeof body)
        return;
    if (send_head(c, code, "text/plain; charset=utf-8", (off_t)n, 0, extra) != 0)
        return;
    if (!is_head)
        (void)conn_write_all(c, body, (size_t)n);
}

/* ------------------------------------------------------------------ */
/* File transmission                                                   */
/* ------------------------------------------------------------------ */

/* Portable fallback: read/write loop starting at `off`.  Adds to *sent.
   Also the only path for TLS, where sendfile(2) cannot be used. */
static int send_file_generic(struct conn *c, int in_fd, off_t off,
                             off_t remaining, off_t *sent)
{
    char buf[COPY_BUF_SIZE];

    if (lseek(in_fd, off, SEEK_SET) == (off_t)-1)
        return -1;
    while (remaining > 0) {
        size_t want = sizeof buf;
        ssize_t n;

        if ((off_t)want > remaining)
            want = (size_t)remaining;
        n = read(in_fd, buf, want);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {              /* file shrank underneath us */
            errno = EIO;
            return -1;
        }
        if (conn_write_all(c, buf, (size_t)n) != 0)
            return -1;
        remaining -= n;
        *sent += n;
    }
    return 0;
}

#if defined(PEWTER_HAVE_SENDFILE)
/* errno values meaning "sendfile cannot do this fd pair / filesystem";
   on these we silently fall back to the generic loop. */
static int sendfile_unsupported(int e)
{
    if (e == EINVAL || e == ENOSYS)
        return 1;
#ifdef ENOTSUP
    if (e == ENOTSUP)
        return 1;
#endif
#ifdef EOPNOTSUPP
    if (e == EOPNOTSUPP)
        return 1;
#endif
    return 0;
}
#endif

/*
 * Send `len` bytes of `in_fd` (from offset 0) to the connection `c`.
 * Returns 0 on success, -1 on error with errno set.  *sent always holds
 * the number of bytes actually transmitted, even on failure.
 *
 * The three supported platforms each have a different sendfile(2)
 * signature and argument order; this wrapper hides that.  Partial sends
 * (EINTR, EAGAIN on a socket with SO_SNDTIMEO) are resumed; EAGAIN with
 * no progress means the client stalled for the whole timeout and is an
 * error.
 */
static int send_file(struct conn *c, int in_fd, off_t len, off_t *sent)
{
    off_t off = 0;

    *sent = 0;

#if defined(PEWTER_TLS)
    if (c->ssl != NULL)
        return send_file_generic(c, in_fd, off, len, sent);
#endif

#if !defined(PEWTER_HAVE_SENDFILE)
    return send_file_generic(c, in_fd, off, len, sent);

#elif defined(__linux__)
    while (off < len) {
        ssize_t n = sendfile(c->fd, in_fd, &off, (size_t)(len - off));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            if (sendfile_unsupported(errno))
                break;
            return -1;
        }
        *sent = off;
        if (n == 0) {
            errno = EIO;
            return -1;
        }
    }
    if (off >= len)
        return 0;
    return send_file_generic(c, in_fd, off, len - off, sent);

#elif defined(__APPLE__)
    while (off < len) {
        off_t chunk = len - off;
        int r = sendfile(in_fd, c->fd, off, &chunk, NULL, 0);
        off += chunk;
        *sent = off;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN) {
                if (chunk > 0)
                    continue;
                return -1;
            }
            if (sendfile_unsupported(errno))
                break;
            return -1;
        }
        if (chunk == 0) {
            errno = EIO;
            return -1;
        }
    }
    if (off >= len)
        return 0;
    return send_file_generic(c, in_fd, off, len - off, sent);

#elif defined(__FreeBSD__)
    while (off < len) {
        off_t sbytes = 0;
        int r = sendfile(in_fd, c->fd, off, (size_t)(len - off), NULL,
                         &sbytes, 0);
        off += sbytes;
        *sent = off;
        if (r < 0) {
            if (errno == EINTR)
                continue;
            if (errno == EAGAIN) {
                if (sbytes > 0)
                    continue;
                return -1;
            }
            if (sendfile_unsupported(errno))
                break;
            return -1;
        }
        if (sbytes == 0) {
            errno = EIO;
            return -1;
        }
    }
    if (off >= len)
        return 0;
    return send_file_generic(c, in_fd, off, len - off, sent);
#endif
}

/* ------------------------------------------------------------------ */
/* Request parsing and path sanitization                               */
/* ------------------------------------------------------------------ */

/* True once `buf` (NUL-terminated) holds an empty line at or after
   `from`, i.e. "\n\n" or "\n\r\n" (RFC 9112 s.2.2 lets a recipient treat a
   bare LF as a line terminator). */
static int head_complete(const char *buf, size_t from)
{
    const char *p = buf + from;

    while ((p = strchr(p, '\n')) != NULL) {
        if (p[1] == '\n' || (p[1] == '\r' && p[2] == '\n'))
            return 1;
        p++;
    }
    return 0;
}

/* Read until the end of the request head.  Returns 0 or an HTTP status. */
static int read_request(struct conn *c, char *buf, size_t bufsz)
{
    size_t total = 0;

    for (;;) {
        ssize_t n;
        size_t scan_from;

        if (total >= bufsz - 1) {
            /* No line ending yet means the request line alone is too
               long (414); otherwise the header section is (431). */
            return memchr(buf, '\n', total) == NULL ? 414 : 431;
        }
        n = conn_read(c, buf + total, bufsz - 1 - total);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return 408;            /* SO_RCVTIMEO expired or socket error */
        }
        if (n == 0)
            return 400;            /* client closed before finishing      */
        if (memchr(buf + total, '\0', (size_t)n) != NULL)
            return 400;            /* NUL bytes are never valid in a head */
        scan_from = total >= 3 ? total - 3 : 0;
        total += (size_t)n;
        buf[total] = '\0';
        if (head_complete(buf, scan_from))
            return 0;
    }
}

static int is_digit(int c)
{
    return c >= '0' && c <= '9';
}

/* tchar (RFC 9110 s.5.6.2): what methods and field names are made of. */
static int is_tchar(int c)
{
    if (is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        return 1;
    return c != '\0' && strchr("!#$%&'*+-.^_`|~", c) != NULL;
}

/* What a Host value or an absolute-form authority may contain
   (RFC 3986 s.3.2: unreserved, sub-delims, pct-encoded, ":", "[", "]"). */
static int is_host_char(int c)
{
    if (is_digit(c) || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'))
        return 1;
    return c != '\0' && strchr("-._~%:[]!$&'()*+,;=", c) != NULL;
}

/* Status for a method other than GET/HEAD: 405 for the methods RFC 9110
   defines, 501 for any other valid token, 400 for a non-token. */
static int method_status(const char *m)
{
    static const char *const known[] = {
        "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"
    };
    size_t i;
    const char *p;

    if (*m == '\0')
        return 400;
    for (p = m; *p != '\0'; p++)
        if (!is_tchar((unsigned char)*p))
            return 400;
    for (i = 0; i < sizeof known / sizeof known[0]; i++)
        if (strcmp(m, known[i]) == 0)
            return 405;
    return 501;
}

/* Reduce an absolute-form request-target (RFC 9112 s.3.2.2) to origin-form
   in place: "http://host:port/a?b" becomes "/a?b", "http://host" becomes
   "/".  origin-form targets pass through; anything else is 400. */
static int absolute_to_origin(char **target)
{
    char *p = *target;

    if (p[0] == '/')
        return 0;
    if (strncasecmp(p, "http://", 7) == 0)
        p += 7;
    else if (strncasecmp(p, "https://", 8) == 0)
        p += 8;
    else
        return 400;
    if (*p == '\0' || *p == '/' || *p == '?')
        return 400;                /* empty authority */
    while (*p != '\0' && *p != '/' && *p != '?') {
        if (!is_host_char((unsigned char)*p) && *p != '@')
            return 400;
        p++;
    }
    if (*p != '/') {
        /* Empty path: the last authority byte is no longer needed, so it
           becomes the leading "/" of the origin-form. */
        p--;
        *p = '/';
    }
    *target = p;
    return 0;
}

/* Split the request line in place and locate the header section.
   Returns 0 or an HTTP status.  *method and *target are set whenever the
   line had the right shape so the caller can log them even for 405/505.
   *http11 reports whether HTTP/1.1 rules (Host required) apply. */
static int parse_request(char *buf, const char **method, char **target,
                         int *is_head, int *http11, char **headers)
{
    char *line_end;
    char *sp1;
    char *sp2;
    const char *version;

    /* RFC 9112 s.2.2: ignore one empty line before the request-line. */
    if (buf[0] == '\r' && buf[1] == '\n')
        buf += 2;
    else if (buf[0] == '\n')
        buf += 1;

    line_end = strchr(buf, '\n');
    if (line_end == NULL)
        return 400;
    *headers = line_end + 1;
    if (line_end > buf && line_end[-1] == '\r')
        line_end--;
    *line_end = '\0';
    if (strchr(buf, '\r') != NULL)
        return 400;                /* bare CR (RFC 9112 s.2.2) */

    sp1 = strchr(buf, ' ');
    if (sp1 == NULL)
        return 400;
    *sp1 = '\0';
    sp2 = strchr(sp1 + 1, ' ');
    if (sp2 == NULL)
        return 400;
    *sp2 = '\0';
    version = sp2 + 1;

    *method = buf;
    *target = sp1 + 1;
    if (**target == '\0')
        return 400;

    /* HTTP-version = "HTTP/" DIGIT "." DIGIT (RFC 9112 s.2.3).  Any 1.x
       above 1.1 is handled as 1.1; other major versions get 505. */
    if (strncmp(version, "HTTP/", 5) != 0 || !is_digit(version[5]) ||
        version[6] != '.' || !is_digit(version[7]) || version[8] != '\0')
        return 400;
    if (version[5] != '1')
        return 505;
    *http11 = version[7] != '0';

    if (strcmp(buf, "GET") == 0)
        *is_head = 0;
    else if (strcmp(buf, "HEAD") == 0)
        *is_head = 1;
    else
        return method_status(buf);
    return absolute_to_origin(target);
}

/* Validate the header section (RFC 9112 s.5) and enforce the few fields
   that matter for framing or are mandatory.  Nothing else is needed:
   every connection carries one request and is closed afterwards, so any
   request body is drained, never read.  Returns 0 or an HTTP status. */
static int parse_headers(char *p, int http11)
{
    int hosts = 0;
    int chunked = 0;
    const char *clen = NULL;

    for (;;) {
        char *name = p;
        char *eol;
        char *colon;
        char *val;
        char *vend;
        char *q;

        eol = strchr(p, '\n');
        if (eol == NULL)
            return 400;
        p = eol + 1;
        if (eol > name && eol[-1] == '\r')
            eol--;
        *eol = '\0';
        if (*name == '\0')
            break;                             /* end of header section */
        if (*name == ' ' || *name == '\t')
            return 400;                        /* obs-fold (s.5.2)       */
        colon = strchr(name, ':');
        if (colon == NULL || colon == name)
            return 400;
        *colon = '\0';
        for (q = name; *q != '\0'; q++)
            if (!is_tchar((unsigned char)*q))
                return 400;                    /* covers "Host :" (s.5.1) */
        val = colon + 1;
        while (*val == ' ' || *val == '\t')
            val++;
        vend = eol;
        while (vend > val && (vend[-1] == ' ' || vend[-1] == '\t'))
            vend--;
        *vend = '\0';
        for (q = val; *q != '\0'; q++) {
            unsigned char c = (unsigned char)*q;
            if ((c < 0x20 && c != '\t') || c == 0x7f)
                return 400;                    /* CTL, incl. a bare CR   */
        }

        if (strcasecmp(name, "Host") == 0) {
            hosts++;
            for (q = val; *q != '\0'; q++)
                if (!is_host_char((unsigned char)*q))
                    return 400;
        } else if (strcasecmp(name, "Content-Length") == 0) {
            if (*val == '\0')
                return 400;
            for (q = val; *q != '\0'; q++)
                if (!is_digit((unsigned char)*q))
                    return 400;
            if (clen != NULL && strcmp(clen, val) != 0)
                return 400;                    /* differing values (s.6.3) */
            clen = val;
        } else if (strcasecmp(name, "Transfer-Encoding") == 0) {
            if (strcasecmp(val, "chunked") != 0)
                return 501;                    /* unknown coding (s.6.1)  */
            chunked = 1;
        }
    }

    if (hosts > 1 || (http11 && hosts == 0))
        return 400;                            /* s.3.2 */
    if (chunked && clen != NULL)
        return 400;                            /* s.6.1 */
    if (clen != NULL) {
        while (*clen == '0')
            clen++;
        if (strlen(clen) > 7)
            return 413;                        /* > 9,999,999: not drained */
    }
    return 0;
}

static int hexval(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/*
 * Turn the request target into a clean absolute path inside the chroot.
 *
 *   - the query is dropped; a fragment or a raw non-ASCII byte is 400
 *   - percent-escapes are decoded; malformed escapes, NUL and any control
 *     byte are rejected
 *   - "//" collapses; "." and ".." segments are rejected outright (so
 *     "%2e%2e" is caught too, because decoding happens first)
 *   - any other segment starting with "." is treated as not found, which
 *     hides .git, .htpasswd, .env and friends
 *
 * The kernel's chroot is the real boundary; this is defense in depth.
 * Returns 0 or an HTTP status.  *trailing_slash reports whether the
 * target named a directory ("/foo/" or "/").
 */
static int sanitize_path(const char *target, char *clean, size_t cleansz,
                         int *trailing_slash)
{
    char dec[MAX_PATH_LEN];
    size_t di = 0;
    size_t i;
    size_t ci;
    const char *p;

    if (target[0] != '/' || cleansz < 2)
        return 400;

    for (p = target; *p != '\0' && *p != '?'; p++) {
        unsigned char c = (unsigned char)*p;
        if (c == '#' || c >= 0x80)
            return 400;            /* no fragment; raw bytes must be ASCII */
        if (c == '%') {
            int h = hexval((unsigned char)p[1]);
            int l = h < 0 ? -1 : hexval((unsigned char)p[2]);
            if (h < 0 || l < 0)
                return 400;
            c = (unsigned char)(h * 16 + l);
            p += 2;
        }
        if (c < 0x20 || c == 0x7f)
            return 400;
        if (di + 1 >= sizeof dec)
            return 414;
        dec[di++] = (char)c;
    }
    dec[di] = '\0';
    *trailing_slash = (di > 0 && dec[di - 1] == '/');

    ci = 0;
    clean[ci++] = '/';
    i = 1;
    while (i < di) {
        size_t j = i;
        size_t n;

        while (j < di && dec[j] != '/')
            j++;
        n = j - i;
        if (n == 0) {                  /* empty segment from "//" */
            i = j + 1;
            continue;
        }
        if (dec[i] == '.') {
            if (n == 1 || (n == 2 && dec[i + 1] == '.'))
                return 400;            /* "." or ".." */
            return 404;                /* dotfile */
        }
        if (ci + n + 1 >= cleansz)
            return 414;
        if (ci > 1)
            clean[ci++] = '/';
        memcpy(clean + ci, dec + i, n);
        ci += n;
        i = j + 1;
    }
    clean[ci] = '\0';
    return 0;
}

/* Percent-encode everything outside the unreserved set so a clean path
   can be placed in a Location header. */
static int url_encode_path(const char *in, char *out, size_t outsz)
{
    static const char hex[] = "0123456789ABCDEF";
    size_t o = 0;

    for (; *in != '\0'; in++) {
        unsigned char c = (unsigned char)*in;
        int safe = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                   (c >= '0' && c <= '9') || c == '-' || c == '.' ||
                   c == '_' || c == '~' || c == '/';
        if (safe) {
            if (o + 1 >= outsz)
                return -1;
            out[o++] = (char)c;
        } else {
            if (o + 3 >= outsz)
                return -1;
            out[o++] = '%';
            out[o++] = hex[(c >> 4) & 0x0f];
            out[o++] = hex[c & 0x0f];
        }
    }
    out[o] = '\0';
    return 0;
}

struct mime_entry {
    const char *ext;
    const char *type;
};

static const struct mime_entry mime_table[] = {
    { "html",  "text/html; charset=utf-8" },
    { "htm",   "text/html; charset=utf-8" },
    { "css",   "text/css; charset=utf-8" },
    { "js",    "text/javascript; charset=utf-8" },
    { "mjs",   "text/javascript; charset=utf-8" },
    { "json",  "application/json" },
    { "txt",   "text/plain; charset=utf-8" },
    { "md",    "text/markdown; charset=utf-8" },
    { "xml",   "application/xml" },
    { "svg",   "image/svg+xml" },
    { "png",   "image/png" },
    { "jpg",   "image/jpeg" },
    { "jpeg",  "image/jpeg" },
    { "gif",   "image/gif" },
    { "webp",  "image/webp" },
    { "ico",   "image/x-icon" },
    { "pdf",   "application/pdf" },
    { "wasm",  "application/wasm" },
    { "woff",  "font/woff" },
    { "woff2", "font/woff2" },
    { "ttf",   "font/ttf" },
    { "mp4",   "video/mp4" },
    { "webm",  "video/webm" },
    { "mp3",   "audio/mpeg" },
    { "ogg",   "audio/ogg" },
    { "zip",   "application/zip" },
    { "gz",    "application/gzip" },
    { "tar",   "application/x-tar" }
};

static const char *content_type(const char *path)
{
    const char *dot = strrchr(path, '.');
    const char *slash = strrchr(path, '/');
    size_t i;

    if (dot == NULL || dot[1] == '\0' || (slash != NULL && slash > dot))
        return "application/octet-stream";
    for (i = 0; i < sizeof mime_table / sizeof mime_table[0]; i++)
        if (strcasecmp(dot + 1, mime_table[i].ext) == 0)
            return mime_table[i].type;
    return "application/octet-stream";
}

/* ------------------------------------------------------------------ */
/* Per-connection child                                                */
/* ------------------------------------------------------------------ */

/* Lingering close.  If the client is still sending (an oversized head, a
   POST body we never read) when we close(), the kernel answers with RST
   and the client may never see our response.  So after shutdown(SHUT_WR)
   read and discard what is left, bounded both in bytes and in time (the
   per-child alarm still caps everything). */
#define DRAIN_LIMIT   (1024 * 1024)
#define DRAIN_SECONDS 2

static void drain_input(int cfd)
{
    char buf[4096];
    size_t total = 0;
    struct timeval tv;

    tv.tv_sec = DRAIN_SECONDS;
    tv.tv_usec = 0;
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    while (total < DRAIN_LIMIT) {
        ssize_t n = recv(cfd, buf, sizeof buf, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            break;
        }
        total += (size_t)n;
    }
}

#if defined(PEWTER_TLS)
/* ------------------------------------------------------------------ */
/* TLS                                                                 */
/* ------------------------------------------------------------------ */

/* First queued library error as text, or errno if the queue is empty. */
static const char *tls_errstr(char *buf, size_t sz)
{
    unsigned long e = ERR_get_error();

    ERR_clear_error();
    if (e != 0)
        ERR_error_string_n(e, buf, sz);
    else
        snprintf(buf, sz, "%s", errno != 0 ? strerror(errno)
                                           : "connection closed");
    return buf;
}

/* The private key is read before chroot and anything under the document
   root is served to anyone who asks, so refuse that combination outright. */
static void check_key_outside_docroot(const char *key, const char *docroot)
{
    char rk[PATH_MAX];
    char rd[PATH_MAX];
    size_t n;

    if (realpath(key, rk) == NULL)
        fatal("%s: %s", key, strerror(errno));
    if (realpath(docroot, rd) == NULL)
        fatal("%s: %s", docroot, strerror(errno));
    n = strlen(rd);
    if (n == 1 && rd[0] == '/')
        n = 0;
    if (strncmp(rk, rd, n) == 0 && rk[n] == '/')
        fatal("private key %s is inside the document root %s and would be "
              "served; move it", key, docroot);
}

/* Build the server context.  Runs once in the parent before chroot and
   privilege drop; the key material it loads is inherited by every child. */
static void tls_init(const char *cert, const char *key)
{
    char err[256];
    unsigned char seed[16];

    g_tls = SSL_CTX_new(TLS_server_method());
    if (g_tls == NULL)
        fatal("SSL_CTX_new: %s", tls_errstr(err, sizeof err));
    if (SSL_CTX_set_min_proto_version(g_tls, TLS1_2_VERSION) != 1)
        fatal("cannot require TLS 1.2: %s", tls_errstr(err, sizeof err));
    (void)SSL_CTX_set_options(g_tls,
                              SSL_OP_NO_COMPRESSION |
                              SSL_OP_CIPHER_SERVER_PREFERENCE |
                              SSL_OP_NO_TICKET |
                              TLS_OPT_NO_RENEGOTIATION |
                              TLS_OPT_IGNORE_UNEXPECTED_EOF);
    /* One request per connection and a fresh process each time: nothing
       to resume, so keep no session state and hand out no tickets. */
    (void)SSL_CTX_set_session_cache_mode(g_tls, SSL_SESS_CACHE_OFF);
#if (defined(LIBRESSL_VERSION_NUMBER) && LIBRESSL_VERSION_NUMBER >= 0x3040000fL) || \
    (!defined(LIBRESSL_VERSION_NUMBER) && OPENSSL_VERSION_NUMBER >= 0x10101000L)
    SSL_CTX_set_num_tickets(g_tls, 0);
#endif
    if (SSL_CTX_set_cipher_list(g_tls, TLS_CIPHERS) != 1)
        fatal("no usable cipher in \"%s\": %s", TLS_CIPHERS,
              tls_errstr(err, sizeof err));
    if (SSL_CTX_use_certificate_chain_file(g_tls, cert) != 1)
        fatal("cannot load certificate %s: %s", cert,
              tls_errstr(err, sizeof err));
    if (SSL_CTX_use_PrivateKey_file(g_tls, key, SSL_FILETYPE_PEM) != 1)
        fatal("cannot load private key %s: %s", key,
              tls_errstr(err, sizeof err));
    if (SSL_CTX_check_private_key(g_tls) != 1)
        fatal("private key %s does not match certificate %s", key, cert);
    /* Seed the DRBG while the real filesystem is still reachable.  Modern
       libraries use getrandom/getentropy, but do not depend on it. */
    if (RAND_bytes(seed, (int)sizeof seed) != 1)
        fatal("cannot seed the random generator: %s",
              tls_errstr(err, sizeof err));
}

/* Run the handshake on a freshly accepted socket.  Returns 0 on success;
   400 when the client spoke plain HTTP to the HTTPS port, in which case
   c->ssl is NULL and the caller answers in the clear; -1 (already logged)
   on any other failure. */
static int tls_accept(struct conn *c, const char *ip)
{
    char err[256];
    unsigned char first;
    ssize_t n;

    /* Peek at the first byte before starting the handshake.  TLS records
       begin with a content type (0x14-0x17); an upper-case ASCII letter is
       an HTTP method from a client that spoke plain HTTP to the HTTPS port.
       Decided here rather than from the library's error reason, which
       differs between OpenSSL and LibreSSL.  If the peek fails the
       handshake runs and reports the problem as usual. */
    do {
        n = recv(c->fd, &first, 1, MSG_PEEK);
    } while (n < 0 && errno == EINTR);
    if (n == 1 && first >= 'A' && first <= 'Z')
        return 400;

    c->ssl = SSL_new(g_tls);
    if (c->ssl == NULL || SSL_set_fd(c->ssl, c->fd) != 1) {
        logmsg("%s tls: %s", ip, tls_errstr(err, sizeof err));
        SSL_free(c->ssl);
        c->ssl = NULL;
        return -1;
    }
    errno = 0;
    if (SSL_accept(c->ssl) == 1)
        return 0;
    SSL_free(c->ssl);
    c->ssl = NULL;
    logmsg("%s tls handshake failed: %s", ip, tls_errstr(err, sizeof err));
    return -1;
}

/* Send close_notify (without waiting for the peer's) and free the session.
   The raw socket is drained and closed by the caller as usual. */
static void tls_close(struct conn *c)
{
    if (c->ssl != NULL) {
        (void)SSL_shutdown(c->ssl);
        SSL_free(c->ssl);
        c->ssl = NULL;
    }
}
#endif /* PEWTER_TLS */

/* ------------------------------------------------------------------ */
/* Request handling                                                    */
/* ------------------------------------------------------------------ */

/* A sanitized path is absolute ("/a/b").  Children look it up relative to
   g_rootfd, the chroot's root, because a Capsicum sandbox refuses absolute
   paths; "/" itself becomes ".". */
static const char *rel_path(const char *path)
{
    return path[1] != '\0' ? path + 1 : ".";
}

static void handle_client(int cfd, const struct sockaddr_storage *ss)
{
    struct conn c;
    char ip[INET6_ADDRSTRLEN];
    char req[REQ_BUF_SIZE];
    char clean[MAX_PATH_LEN];
    char fspath[MAX_PATH_LEN + 16];
    char safe_target[LOG_TARGET_LEN];
    char safe_method[LOG_METHOD_LEN];
    const char *method = "-";
    char *target = NULL;
    char *hdrs = NULL;
    int is_head = 0;
    int http11 = 0;
    int trailing = 0;
    int status;
    int fd = -1;
    int n;
    struct stat st;
    struct timeval tv;
    off_t sent = 0;

    /* Hard upper bound on the life of this child: SIGALRM's default
       disposition terminates the process. */
    alarm((unsigned int)g_timeout);
    tv.tv_sec = g_timeout;
    tv.tv_usec = 0;
    (void)setsockopt(cfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
    (void)setsockopt(cfd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);

    client_ip(ss, ip, sizeof ip);
    memset(&st, 0, sizeof st);
    c.fd = cfd;
    status = 0;
#if defined(PEWTER_TLS)
    c.ssl = NULL;
    if (g_tls != NULL) {
        status = tls_accept(&c, ip);
        if (status < 0) {
            close(cfd);
            return;
        }
    }
#endif

    if (status == 0)
        status = read_request(&c, req, sizeof req);
    if (status == 0)
        status = parse_request(req, &method, &target, &is_head, &http11,
                               &hdrs);
    if (status == 0)
        status = parse_headers(hdrs, http11);
    if (status == 0)
        status = sanitize_path(target, clean, sizeof clean, &trailing);
    if (status == 0) {
        if (trailing)
            n = snprintf(fspath, sizeof fspath, "%s%sindex.html", clean,
                         clean[1] == '\0' ? "" : "/");
        else
            n = snprintf(fspath, sizeof fspath, "%s", clean);
        if (n < 0 || (size_t)n >= sizeof fspath)
            status = 414;
    }
    if (status == 0) {
        /* O_NONBLOCK so a FIFO in the document root cannot park the child
           in open() until the alarm fires; it is cleared again below once
           the file is known to be regular. */
        fd = openat(g_rootfd, rel_path(fspath),
                    O_RDONLY | O_CLOEXEC | O_NONBLOCK);
        if (fd < 0) {
            if (errno == ENOENT || errno == ENOTDIR) {
                struct stat ds;
                status = 404;
                /* "/dir/" whose index.html is missing: the directory
                   exists but we refuse to list it. */
                if (trailing && fstatat(g_rootfd, rel_path(clean), &ds, 0) == 0
                    && S_ISDIR(ds.st_mode))
                    status = 403;
            } else if (errno == EACCES) {
                status = 403;
#if defined(ENOTCAPABLE)
            } else if (errno == ENOTCAPABLE) {
                status = 403;      /* a symlink leading out of the sandbox */
#endif
            } else if (errno == ENAMETOOLONG) {
                status = 414;      /* a segment longer than NAME_MAX */
            } else {
                status = 500;
            }
        } else if (fstat(fd, &st) != 0) {
            status = 500;
        } else if (S_ISDIR(st.st_mode)) {
            status = trailing ? 403 : 301;
        } else if (!S_ISREG(st.st_mode)) {
            status = 403;
        } else {
            int fl = fcntl(fd, F_GETFL);
            if (fl >= 0)
                (void)fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
        }
    }

    switch (status) {
    case 0:
        status = 200;
        if (send_head(&c, 200, content_type(fspath), st.st_size,
                      st.st_mtime, NULL) == 0 && !is_head) {
            if (send_file(&c, fd, st.st_size, &sent) != 0)
                logmsg("%s: send_file: %s", ip, strerror(errno));
        }
        break;
    case 301: {
        char enc[ENC_PATH_LEN];
        char loc[ENC_PATH_LEN + 32];
        if (url_encode_path(clean, enc, sizeof enc) != 0) {
            status = 414;
            send_error(&c, status, is_head, NULL);
            break;
        }
        n = snprintf(loc, sizeof loc, "Location: %s/\r\n", enc);
        if (n < 0 || (size_t)n >= sizeof loc) {
            status = 414;
            send_error(&c, status, is_head, NULL);
            break;
        }
        send_error(&c, 301, is_head, loc);
        break;
    }
    case 405:
        send_error(&c, 405, is_head, "Allow: GET, HEAD\r\n");
        break;
    default:
        send_error(&c, status, is_head, NULL);
        break;
    }

    if (fd >= 0)
        close(fd);
#if defined(PEWTER_TLS)
    tls_close(&c);
#endif
    (void)shutdown(cfd, SHUT_WR);
    drain_input(cfd);
    close(cfd);

    /* The method is whatever token the client sent (a 400/501 logs it
       raw), so it gets the same treatment as the target. */
    log_safe(method, safe_method, sizeof safe_method);
    log_safe(target != NULL ? target : "-", safe_target, sizeof safe_target);
    logmsg("%s \"%s %s\" %d %lu", ip, safe_method, safe_target, status,
           (unsigned long)sent);
}

/* ------------------------------------------------------------------ */
/* Signals                                                             */
/* ------------------------------------------------------------------ */

static void on_sigchld(int sig)
{
    int saved = errno;
    (void)sig;
    for (;;) {
        pid_t p = waitpid(-1, NULL, WNOHANG);
        if (p <= 0)
            break;
        if (g_active_children > 0)
            g_active_children--;
    }
    errno = saved;
}

static void on_quit(int sig)
{
    (void)sig;
    g_quit = 1;
}

static void set_handler(int sig, void (*fn)(int), int flags)
{
    struct sigaction sa;
    memset(&sa, 0, sizeof sa);
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = fn;
    sa.sa_flags = flags;
    if (sigaction(sig, &sa, NULL) != 0)
        fatal("sigaction(%d): %s", sig, strerror(errno));
}

static void install_signals(void)
{
    set_handler(SIGCHLD, on_sigchld, SA_RESTART | SA_NOCLDSTOP);
    set_handler(SIGTERM, on_quit, 0);     /* no SA_RESTART: accept() must  */
    set_handler(SIGINT, on_quit, 0);      /* return EINTR so we notice     */
    set_handler(SIGPIPE, SIG_IGN, 0);     /* EPIPE from write() instead    */
}

/* ------------------------------------------------------------------ */
/* Startup: listener, chroot, privilege drop                           */
/* ------------------------------------------------------------------ */

/* Make sure 0, 1 and 2 are open so accept() can never hand us a socket
   on a standard descriptor.  Must run before chroot (needs /dev/null). */
static void ensure_std_fds(void)
{
    int i;
    for (i = 0; i <= 2; i++) {
        if (fcntl(i, F_GETFD) == -1 && errno == EBADF) {
            int fd = open("/dev/null", O_RDWR);
            if (fd != i)
                fatal("cannot reopen fd %d on /dev/null", i);
        }
    }
}

static int open_listener(const char *addr, const char *port)
{
    struct addrinfo hints;
    struct addrinfo *res;
    struct addrinfo *ai;
    int fd = -1;
    int rc;
    int one = 1;
    int saved_errno = 0;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags = AI_PASSIVE | AI_NUMERICHOST | AI_NUMERICSERV;
    rc = getaddrinfo(addr, port, &hints, &res);
    if (rc != 0)
        fatal("getaddrinfo(%s, %s): %s", addr, port, gai_strerror(rc));

    for (ai = res; ai != NULL; ai = ai->ai_next) {
        fd = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (fd < 0) {
            saved_errno = errno;
            continue;
        }
        (void)setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof one);
#ifdef IPV6_V6ONLY
        if (ai->ai_family == AF_INET6) {
            int zero = 0;
            (void)setsockopt(fd, IPPROTO_IPV6, IPV6_V6ONLY, &zero, sizeof zero);
        }
#endif
        if (bind(fd, ai->ai_addr, ai->ai_addrlen) == 0 &&
            listen(fd, LISTEN_BACKLOG) == 0)
            break;
        saved_errno = errno;
        close(fd);
        fd = -1;
    }
    freeaddrinfo(res);
    if (fd < 0)
        fatal("cannot listen on %s port %s: %s", addr, port,
              strerror(saved_errno));
    (void)fcntl(fd, F_SETFD, FD_CLOEXEC);
    return fd;
}

static void enter_chroot(const char *docroot)
{
    /* chdir first, then chroot(".") so the directory we lock into is
       exactly the one we checked, with no path re-resolution in between. */
    if (chdir(docroot) != 0)
        fatal("chdir(%s): %s", docroot, strerror(errno));
    if (chroot(".") != 0)
        fatal("chroot(%s): %s", docroot, strerror(errno));
    if (chdir("/") != 0)
        fatal("chdir(/) after chroot: %s", strerror(errno));

    /* Children inherit this descriptor and open every file through it
       with openat(2), which is all a Capsicum sandbox allows. */
    g_rootfd = open(".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (g_rootfd < 0)
        fatal("open(/) after chroot: %s", strerror(errno));
#if defined(__FreeBSD__)
    {
        /* Files opened through a capability inherit its rights, so this
           also limits every file a child serves: look up, read, seek,
           stat and set O_NONBLOCK.  Nothing that writes or creates. */
        cap_rights_t rights;
        /* The CAP_ constants are unsigned long long, not C89. */
        EXTENSION cap_rights_init(&rights, CAP_LOOKUP, CAP_PREAD, CAP_FSTAT,
                                  CAP_FSTATAT, CAP_FCNTL);
        if (cap_rights_limit(g_rootfd, &rights) != 0)
            fatal("cap_rights_limit: %s", strerror(errno));
    }
#endif
}

static void drop_privileges(uid_t uid, gid_t gid)
{
    if (setgroups(1, &gid) != 0)
        fatal("setgroups: %s", strerror(errno));
    if (setgid(gid) != 0)
        fatal("setgid(%lu): %s", (unsigned long)gid, strerror(errno));
    if (setuid(uid) != 0)
        fatal("setuid(%lu): %s", (unsigned long)uid, strerror(errno));

    /* Verify the drop is real and irreversible. */
    if (setuid(0) != -1 || setgid(0) != -1)
        fatal("privileges could be regained after dropping them; aborting");
    if (getuid() != uid || geteuid() != uid ||
        getgid() != gid || getegid() != gid)
        fatal("privilege drop verification failed");

#if defined(__linux__) && defined(PR_SET_NO_NEW_PRIVS)
    (void)prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
#endif
#if defined(__FreeBSD__)
    {
        int arg;
#  if defined(PROC_NO_NEW_PRIVS_CTL)       /* FreeBSD 14 and later */
        arg = PROC_NO_NEW_PRIVS_ENABLE;
        (void)procctl(P_PID, getpid(), PROC_NO_NEW_PRIVS_CTL, &arg);
#  endif
        /* No ptrace(2) attach and no core dumps, for this process and every
           child it forks: each of them holds the TLS private key.  The
           kernel already refuses both for a process that changed its
           credentials; this does not depend on that. */
        arg = PROC_TRACE_CTL_DISABLE;
        (void)procctl(P_PID, getpid(), PROC_TRACE_CTL, &arg);
    }
#endif
}

#if defined(PEWTER_HAVE_SECCOMP)
/* ------------------------------------------------------------------ */
/* Linux: seccomp filter for the children                              */
/* ------------------------------------------------------------------ */

/* What a child may still do once chrooted and unprivileged, as a list of
   system calls; anything else kills it.  Chroot already confines paths,
   which seccomp cannot inspect, so the filter's job is the rest: no new
   sockets or connections, no signals to other processes, no exec, no
   ptrace, nothing opened for writing, no executable memory, and far less
   of the kernel within reach. */

#if defined(__x86_64__)
#  define SC_AUDIT_ARCH AUDIT_ARCH_X86_64
#elif defined(__aarch64__)
#  define SC_AUDIT_ARCH AUDIT_ARCH_AARCH64
#endif

#define SC_MAX_INSNS 256             /* about 115 used on x86_64 */
/* Low 32 bits of syscall argument i; both architectures are little-endian.
   Every argument checked below is an int, of which the kernel uses only
   those bits. */
#define SC_ARG_LO(i) (offsetof(struct seccomp_data, args) + (i) * 8)
/* openat/open flags that could create, truncate or write a file. */
#define SC_WRITE_FLAGS (O_ACCMODE | O_CREAT | O_TRUNC | O_APPEND)

/* Allowed unconditionally. */
static const long sc_allowed[] = {
    /* I/O on descriptors the child already holds.  sendto is send(); with
       no socket() a destination address has nowhere to go.  writev is
       glibc's "stack smashing detected" message. */
    __NR_read, __NR_write, __NR_writev, __NR_pread64, __NR_lseek,
    __NR_recvfrom, __NR_sendto, __NR_sendfile, __NR_setsockopt,
    __NR_shutdown, __NR_fcntl, __NR_close,
    /* fstat, and fstatat beneath the root; libcs differ in which they use */
    __NR_fstat, __NR_newfstatat, __NR_statx,
    /* memory for malloc in libc and the TLS library (mmap and mprotect
       are allowed below, without PROT_EXEC) */
    __NR_brk, __NR_munmap, __NR_mremap, __NR_madvise, __NR_futex,
    /* time, the per-child alarm (setitimer on aarch64 and in musl),
       randomness for TLS */
    __NR_clock_gettime, __NR_gettimeofday, __NR_setitimer, __NR_getrandom,
    /* own identity, abort(), exit */
    __NR_getpid, __NR_gettid, __NR_rt_sigprocmask, __NR_rt_sigreturn,
    __NR_restart_syscall, __NR_exit, __NR_exit_group,
#if defined(__x86_64__)
    __NR_alarm, __NR_time,     /* not in the aarch64 syscall table */
#endif
    -1
};

struct sc_prog {
    struct sock_filter insn[SC_MAX_INSNS];
    unsigned short n;
    int overflow;
};

static void sc_emit(struct sc_prog *p, unsigned int code, unsigned int jt,
                    unsigned int jf, unsigned long k)
{
    struct sock_filter *f;
    if (p->n >= SC_MAX_INSNS) {
        p->overflow = 1;
        return;
    }
    f = &p->insn[p->n++];
    f->code = (__u16)code;
    f->jt = (__u8)jt;
    f->jf = (__u8)jf;
    f->k = (__u32)k;
}

/* With the syscall number in the accumulator: allow syscall nr. */
static void sc_allow(struct sc_prog *p, long nr)
{
    sc_emit(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, (unsigned long)nr);
    sc_emit(p, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
}

/* Allow syscall nr only if (argument arg & mask) == want, else kill.  A
   different syscall jumps over the block with the number still loaded. */
static void sc_allow_if(struct sc_prog *p, long nr, unsigned int arg,
                        unsigned long mask, unsigned long want)
{
    sc_emit(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 5, (unsigned long)nr);
    sc_emit(p, BPF_LD | BPF_W | BPF_ABS, 0, 0, SC_ARG_LO(arg));
    sc_emit(p, BPF_ALU | BPF_AND | BPF_K, 0, 0, mask);
    sc_emit(p, BPF_JMP | BPF_JEQ | BPF_K, 0, 1, want);
    sc_emit(p, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_ALLOW);
    sc_emit(p, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
}

static int install_seccomp(void)
{
    struct sc_prog p;
    struct sock_fprog prog;
    unsigned long self = (unsigned long)getpid();
    size_t i;

    p.n = 0;
    p.overflow = 0;

    /* A syscall made under another ABI has other numbers: kill it. */
    sc_emit(&p, BPF_LD | BPF_W | BPF_ABS, 0, 0,
            offsetof(struct seccomp_data, arch));
    sc_emit(&p, BPF_JMP | BPF_JEQ | BPF_K, 1, 0, SC_AUDIT_ARCH);
    sc_emit(&p, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
    sc_emit(&p, BPF_LD | BPF_W | BPF_ABS, 0, 0,
            offsetof(struct seccomp_data, nr));
#if defined(__x86_64__)
    /* x32 shares AUDIT_ARCH_X86_64 and sets bit 30 of the number. */
    sc_emit(&p, BPF_JMP | BPF_JGE | BPF_K, 0, 1, 0x40000000UL);
    sc_emit(&p, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);
#endif

    for (i = 0; sc_allowed[i] != -1; i++)
        sc_allow(&p, sc_allowed[i]);

    /* Files are opened read-only, whatever the permissions would allow. */
    sc_allow_if(&p, __NR_openat, 2, SC_WRITE_FLAGS, O_RDONLY);
#if defined(__x86_64__)
    sc_allow_if(&p, __NR_open, 1, SC_WRITE_FLAGS, O_RDONLY);
#endif
    /* No memory that is executable, so injected code cannot be run. */
    sc_allow_if(&p, __NR_mmap, 2, PROT_EXEC, 0);
    sc_allow_if(&p, __NR_mprotect, 2, PROT_EXEC, 0);
    /* abort() signals itself (-ftrapv, the stack protector); signals to
       any other process, the parent included, are refused. */
    sc_allow_if(&p, __NR_tgkill, 0, 0xffffffffUL, self);
    sc_allow_if(&p, __NR_tkill, 0, 0xffffffffUL, self);

    sc_emit(&p, BPF_RET | BPF_K, 0, 0, SECCOMP_RET_KILL_PROCESS);

    if (p.overflow) {
        errno = E2BIG;
        return -1;
    }
    prog.len = p.n;
    prog.filter = p.insn;
    /* Set by drop_privileges() already; the filter requires it. */
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0)
        return -1;
    return prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog, 0, 0);
}
#endif /* PEWTER_HAVE_SECCOMP */

/* Shrink what a child could do if serving its request were ever subverted.
   Runs right after fork, before the first byte from the client is read
   (the TLS handshake included).  A failure here fails closed: the child
   exits without serving. */
static void sandbox_child(void)
{
    struct rlimit none, fds;
    const char *what = NULL;

    none.rlim_cur = none.rlim_max = 0;
    fds.rlim_cur = fds.rlim_max = CHILD_MAX_FDS;

    /* No core file can ever hold the TLS private key. */
    if (setrlimit(RLIMIT_CORE, &none) != 0)
        what = "RLIMIT_CORE";
    /* A child serves one request and exits; it never needs to fork. */
    else if (setrlimit(RLIMIT_NPROC, &none) != 0)
        what = "RLIMIT_NPROC";
    /* stdio, the client socket, g_rootfd and the file being served. */
    else if (setrlimit(RLIMIT_NOFILE, &fds) != 0)
        what = "RLIMIT_NOFILE";
#if defined(__FreeBSD__)
    /* Capability mode: from here on only the descriptors already held can
       be used.  No new sockets or connections, no signals to other
       processes, no path lookups except beneath g_rootfd. */
    else if (cap_enter() != 0)
        what = "cap_enter";
#endif
#if defined(PEWTER_HAVE_SECCOMP)
    /* The Linux counterpart: from here on only the system calls a child
       needs, see install_seccomp().  Last, so that setrlimit itself need
       not be on the list. */
    else if (install_seccomp() != 0)
        what = "seccomp";
#endif

    if (what != NULL) {
        logmsg("child sandbox: %s: %s", what, strerror(errno));
        _exit(1);
    }
}

/* Turn away a connection the parent will not fork for.  In the clear the
   client gets a 503; over TLS answering would mean a handshake in the
   parent, so the connection is simply closed. */
static void reject_connection(int cfd)
{
    struct conn c;

    c.fd = cfd;
#if defined(PEWTER_TLS)
    c.ssl = NULL;
    if (g_tls != NULL)
        return;
#endif
    send_error(&c, 503, 0, "Retry-After: 1\r\n");
}

static void usage(int status) NORETURN;
static void usage(int status)
{
    FILE *f = status == 0 ? stdout : stderr;
    fputs("usage: " SERVER_NAME " [-a addr] [-p port] [-u user] [-g group]"
          " [-t seconds] [-c max_children]\n"
          "              [-C cert.pem -K key.pem] docroot\n\n", f);
    fputs("  -a addr          listen address (default " DEFAULT_ADDR
          "; use :: for IPv6/dual-stack)\n"
          "  -p port          listen port (default " DEFAULT_PORT ")\n"
          "  -u user          unprivileged user to run as (default "
          DEFAULT_USER ")\n"
          "  -g group         group to run as (default: user's primary group)\n",
          f);
    fputs("  -t seconds       per-connection timeout (default 30)\n"
          "  -c max_children  concurrent connection limit (default 64)\n"
#if defined(PEWTER_TLS)
          "  -C cert.pem      serve HTTPS with this certificate chain (PEM)\n"
          "  -K key.pem       private key for -C (PEM, keep it outside"
          " docroot)\n"
#else
          "  -C, -K           HTTPS: not in this build (make tls)\n"
#endif
          "  -h               this help\n\n"
          "Must be started as root: it chroots into docroot and then drops\n"
          "to the given user before accepting any connection.\n", f);
#if defined(PEWTER_HAVE_SECCOMP)
    fputs("Each connection's child runs under a seccomp syscall"
          " allowlist.\n", f);
#endif
    exit(status);
}

int main(int argc, char **argv)
{
    const char *addr = DEFAULT_ADDR;
    const char *port = DEFAULT_PORT;
    const char *user = DEFAULT_USER;
    const char *group = NULL;
    const char *cert = NULL;
    const char *key = NULL;
    const char *scheme = "http";
    const char *docroot;
    int max_children = DEFAULT_MAX_CHILDREN;
    int opt;
    int lfd;
    uid_t uid;
    gid_t gid;
    struct passwd *pw;
    sigset_t chld_set;
    sigset_t old_set;

    while ((opt = getopt(argc, argv, "a:p:u:g:t:c:C:K:h")) != -1) {
        switch (opt) {
        case 'a': addr = optarg; break;
        case 'p': port = optarg; break;
        case 'u': user = optarg; break;
        case 'g': group = optarg; break;
        case 'C': cert = optarg; break;
        case 'K': key = optarg; break;
        case 't': g_timeout = parse_int(optarg, 1, 3600, "timeout"); break;
        case 'c': max_children = parse_int(optarg, 1, 100000,
                                           "max children"); break;
        case 'h': usage(0);
        default:  usage(1);
        }
    }
    if (optind != argc - 1)
        usage(1);
    docroot = argv[optind];

    if (geteuid() != 0)
        fatal("must be started as root: " SERVER_NAME
              " chroots into the docroot and then drops privileges");

    /* Everything that needs the real filesystem happens before chroot. */
    pw = getpwnam(user);
    if (pw == NULL)
        fatal("unknown user: %s", user);
    uid = pw->pw_uid;
    gid = pw->pw_gid;
    if (group != NULL) {
        struct group *gr = getgrnam(group);
        if (gr == NULL)
            fatal("unknown group: %s", group);
        gid = gr->gr_gid;
    }
    if (uid == 0 || gid == 0)
        fatal("refusing to serve as uid 0 or gid 0 (user %s)", user);

    if ((cert == NULL) != (key == NULL))
        fatal("-C and -K must be given together");
    if (cert != NULL) {
#if defined(PEWTER_TLS)
        check_key_outside_docroot(key, docroot);
        tls_init(cert, key);
        scheme = "https";
#else
        fatal("this build has no TLS support; rebuild with `make tls`");
#endif
    }

    ensure_std_fds();
    umask(077);
    lfd = open_listener(addr, port);
    install_signals();

    enter_chroot(docroot);
    drop_privileges(uid, gid);

    logmsg("listening on %s port %s (%s), chroot %s, uid %lu gid %lu, "
           "timeout %ds, max children %d",
           addr, port, scheme, docroot, (unsigned long)uid,
           (unsigned long)gid, g_timeout, max_children);

    sigemptyset(&chld_set);
    sigaddset(&chld_set, SIGCHLD);

    while (!g_quit) {
        struct sockaddr_storage ss;
        socklen_t slen = sizeof ss;
        int cfd;
        pid_t pid;

        cfd = accept(lfd, (struct sockaddr *)&ss, &slen);
        if (cfd < 0) {
            if (errno == EINTR || errno == ECONNABORTED)
                continue;
            logmsg("accept: %s", strerror(errno));
            sleep(1);              /* EMFILE/ENFILE: don't spin */
            continue;
        }

        if (g_active_children >= max_children) {
            logmsg("connection limit (%d) reached, rejecting", max_children);
            reject_connection(cfd);
            close(cfd);
            continue;
        }

        /* Block SIGCHLD across fork+increment so a child that exits
           instantly cannot be reaped before it is counted. */
        sigprocmask(SIG_BLOCK, &chld_set, &old_set);
        pid = fork();
        if (pid == 0) {
            sigprocmask(SIG_SETMASK, &old_set, NULL);
            set_handler(SIGCHLD, SIG_DFL, 0);
            set_handler(SIGTERM, SIG_DFL, 0);
            set_handler(SIGINT, SIG_DFL, 0);
            close(lfd);
            sandbox_child();
            handle_client(cfd, &ss);
            _exit(0);
        }
        if (pid > 0) {
            g_active_children++;
        } else {
            logmsg("fork: %s", strerror(errno));
            reject_connection(cfd);
        }
        sigprocmask(SIG_SETMASK, &old_set, NULL);
        close(cfd);
    }

    logmsg("shutting down");
    close(lfd);
    return 0;
}
