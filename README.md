# pewter

A minimal static HTTP server in strict C89 with no dependencies beyond libc.
One process per connection, chrooted into the document root, running as an
unprivileged user. Portable across Linux, macOS and FreeBSD. An optional
build adds HTTPS through OpenSSL or LibreSSL, and a Zig build produces a
fully static Linux binary against musl, with or without HTTPS.

The whole server is a single file, `pewter.c`, written to be read in one
sitting.

## Build

    make            # release: -O2, hardened, every warning as an error
    make debug      # pewter-debug with AddressSanitizer + UBSan
    make tls        # the same pewter binary, with HTTPS support
    make debug-tls  # pewter-debug with HTTPS support
    make kcc        # pewter built with a minimal compiler (KCC=~/bin/kcc)
    make install    # PREFIX=/usr/local by default
    make clean

The Makefile is strictly POSIX, so GNU make, bmake and FreeBSD make all work.
Flag groups are variables you can override:

    make WERROR=                                  # keep warnings non-fatal
    make CC=gcc                                   # another compiler
    make EXTRA=-DPEWTER_NO_SENDFILE               # force the read/write fallback
    make LDFLAGS="-pie -Wl,-z,relro,-z,now"       # extra link hardening (Linux/FreeBSD)

`make kcc` is for compilers that know only `-c -S -o -I -D -U -std=`: it
empties the warning, optimisation, hardening and linker groups and builds
`pewter` from the same source. `make kcc KCC=path/to/cc` picks another
such compiler; the manual equivalent for any compiler is
`make CC=path/to/cc WARN= WERROR= OPT= HARDEN= LDFLAGS=`.

`make debug` needs a toolchain that ships the sanitizer runtimes; Alpine's
musl gcc does not, so run the sanitizer matrix on glibc Linux or macOS.

`make tls` needs OpenSSL 1.1.1 or newer, or LibreSSL, with headers
(Debian: `libssl-dev`; macOS: `brew install openssl`, which also provides
`pkg-config`). The recipe asks `pkg-config` for the include and library
paths and falls back to the system ones. To use a specific install, say a
keg-only Homebrew version, pass the paths explicitly (`-isystem` rather
than `-I`, so the library's headers are exempt from the pedantic C89
checks):

    make tls TLS_INC=-isystem/opt/homebrew/opt/openssl@3/include \
             TLS_LIB=-L/opt/homebrew/opt/openssl@3/lib

`make` and `make tls` both produce `pewter`: the plain build never links
the TLS library, the TLS build is the same source compiled with
`-DPEWTER_TLS` and still serves plain HTTP unless `-C` and `-K` are given.
Because they share a name the `tls` targets always rebuild; `make clean &&
make` returns to the plain build. `pewter -h` says which one you have.

Release builds use `-std=c89 -pedantic-errors`, a broad gcc/clang warning set
under `-Werror`, and keep runtime protections on: stack protector,
`_FORTIFY_SOURCE=2`, PIE, and `-ftrapv` (signed overflow aborts instead of
wrapping).

### Static build with Zig

    zig build                              # static pewter for <host cpu>-linux-musl
    zig build -Dtls                        # the same with HTTPS (static LibreSSL)
    zig build -Dtarget=x86_64-linux-musl   # cross-compile; aarch64-linux-musl etc.

`build.zig` (Zig 0.17) compiles `pewter.c` with the same C89 flag set as the
Makefile and links it statically against musl libc. The result,
`zig-out/bin/pewter`, is a static-PIE ELF: no dynamic loader, no shared
libraries, so it runs on any Linux kernel of that architecture and is the
right thing to copy into an empty container. The plain build is about
115 KB; the HTTPS build about 1.9 MB. The target defaults to Linux/musl on
the host's CPU whatever the host OS, so `zig build` on macOS or glibc Linux
cross-compiles the same binary; macOS has no static executables of its own.
Build state lives in `.zig-cache/`, fetched packages are unpacked into
`zig-pkg/` and the binary goes to `zig-out/`; all three are ignored by git.

| Option | Default | Meaning |
|--------|---------|---------|
| `-Dtls` | false | HTTPS support. Needs network on first use (see below). |
| `-Dtarget=` | host CPU, Linux, musl | Any `<arch>-linux-musl` target. |
| `-Doptimize=` | safe | `safe` is `-O2` with undefined behaviour trapped; `debug` is `-O0` with debug info; `fast`/`small` also work. |
| `-Dstrip=` | true unless debug | Strip symbols and debug info. |
| `-Dsendfile=` | true | `false` defines `PEWTER_NO_SENDFILE`. |

HTTPS needs a TLS library built for musl, which no distribution ships
statically, so `-Dtls` pulls in LibreSSL as a Zig package
([allyourcodebase/libressl](https://github.com/allyourcodebase/libressl),
LibreSSL 4.0.0, pinned by commit and content hash in `build.zig.zon`) and
compiles it into the binary. The dependency is lazy: a plain `zig build`
never downloads anything, and the first `zig build -Dtls` fetches the
package and the LibreSSL release tarball once (about 25 MB unpacked in
`zig-pkg/`).
`zig build --fetch -Dtls` does that step on its own, for a build machine
without network access later. The LibreSSL headers are treated as system
headers so the pedantic C89 checks apply to `pewter.c` only. As with
`make tls`, `pewter -h` says which build you have.

The hardening matches the Makefile: stack protector, `-ftrapv`, PIE
(static-PIE here) and, from Zig's safe mode, `-fsanitize=undefined
-fsanitize-trap=undefined`, so undefined behaviour aborts the child rather
than continuing. `_FORTIFY_SOURCE` is set but musl does not implement it.

## Run

    sudo ./pewter [-a addr] [-p port] [-u user] [-g group] [-t seconds] [-c max_children] docroot
    sudo ./pewter ... -C cert.pem -K key.pem docroot        # make tls / zig build -Dtls

| Option | Default  | Meaning |
|--------|----------|---------|
| `-a`   | 0.0.0.0  | Listen address. Use `::` for IPv6 and dual-stack. |
| `-p`   | 8080     | Listen port. |
| `-u`   | nobody   | User to drop to after chroot. Must not be uid 0. |
| `-g`   | user's   | Group to drop to. Must not be gid 0. |
| `-t`   | 30       | Per-connection timeout in seconds. |
| `-c`   | 64       | Maximum concurrent connections (forked children). |
| `-C`   |          | Certificate chain, PEM. Turns the listener into HTTPS (TLS builds only). |
| `-K`   |          | Private key for `-C`, PEM. Must live outside the document root. |

Examples:

    sudo ./pewter -p 80 -u www -g www /var/www/site
    sudo ./pewter -p 443 -u www -g www \
        -C /etc/ssl/site/fullchain.pem -K /etc/ssl/site/privkey.pem /var/www/site

A listener speaks either HTTP or HTTPS, never both; to serve both, run two
instances. The certificate and key are read once, as root, before the
chroot, so they can sit anywhere readable by root. pewter refuses to start
if the key resolves to a path inside the document root, since everything
under it is served.

Logs go to stderr, one line per request:

    2026-10-07T17:19:22Z [203] 203.0.113.7 "GET /index.html" 200 1532

A failed TLS handshake is logged with the library's reason instead of a
request line.

Send `SIGTERM` or `SIGINT` to stop accepting; in-flight children finish their
one request and exit.

## Test

    make && sudo sh test.sh

`test.sh` builds a throwaway document root, starts the server on 127.0.0.1,
and runs about sixty checks: status codes, headers, traversal and encoding
attacks, malformed request lines, a 20 MB transfer compared by SHA-256, the
slowloris timeout, the connection limit, and that the parent runs as `nobody`
with its root inside the docroot. Needs `curl`, `nc` and `pgrep`.

    make tls && sudo sh test.sh

Given a TLS-capable binary (and `openssl` on the path) it also generates a
self-signed certificate and runs an HTTPS section on the next port: the
same status codes and transfer check over TLS, plain HTTP sent to the HTTPS
port, the negotiated protocol version, TLS 1.1 refusal, the idle-client
timeout during the handshake, and that a key placed inside the docroot is
refused.

The static Zig binaries run the same script on Linux:

    zig build -Dtls && sudo sh test.sh zig-out/bin/pewter

### HTTP conformance

    make debug && sudo python3 conformance.py ./pewter-debug
    make debug-tls && sudo python3 conformance.py --tls ./pewter-debug

`conformance.py` (standard library only) sends about 190 raw requests and
checks the replies against RFC 9110 and RFC 9112: message framing, the
request line and version grammar, absolute-form targets, Host and
Content-Length rules, obs-fold and bare CR, HEAD/GET agreement, 405 `Allow`,
301 `Location`, timeouts, pipelining, incremental delivery, and a block of
path-traversal attempts. Each check is tagged MUST, SHOULD or NOTE with the
RFC section; only MUST failures make the exit status non-zero. The server
log is scanned for sanitizer reports at the end, so running it against
`pewter-debug` doubles as a memory-safety test.

With `--tls` every request goes over HTTPS with a throwaway certificate,
and a TLS block is added: TLS 1.2 or 1.3 negotiated with an AEAD,
forward-secret suite, TLS 1.0 and 1.1 refused, plain HTTP on the HTTPS
port answered with a 400 in the clear, a malformed ClientHello closed, an
idle post-handshake client dropped on the timeout, and `close_notify` sent
before the socket closes.

There is no freely available black-box HTTP/1.1 conformance suite comparable
to h2spec, so the request-side checks are written from the spec. For the
response side, [HTTPolice](https://httpolice.readthedocs.io/) can lint
captured exchanges (`httpolice -i combined`). pewter's responses produce no
HTTPolice errors; the only notice on a response is its assumption that an
absolute-form request was proxied and therefore needs `Via`.

### Fuzzing

    sudo python3 fuzz.py -n 5000 ./pewter-debug      # over the network
    sudo python3 fuzz.py --tls -n 5000 ./pewter-debug    # after make debug-tls
    make fuzz && ./pewter-fuzz -max_len=9000 corpus/  # in-process (clang)

`fuzz.py` throws mutated requests at a live server: half from
[radamsa](https://gitlab.com/akihe/radamsa) if it is installed, the rest from
a built-in generator of hostile request lines, targets, escapes, headers and
bodies, a fifth of them delivered a few bytes at a time. Every reply must be
a well-formed HTTP/1.1 response or a clean close, the parent must survive,
and the log must stay free of sanitizer reports. With `--tls` the cases go
through a TLS session, except a tenth that are thrown at the listener in
the clear to exercise the handshake with hostile bytes.

`make fuzz` builds `fuzz_parse.c`, a libFuzzer harness that feeds arbitrary
bytes straight into the parser functions (request line, headers, path
sanitizer, Location encoder) under ASan/UBSan at tens of thousands of
executions per second. It needs clang with the libFuzzer runtime (Debian:
`clang libclang-rt-dev`); Apple's clang does not ship it.

### Running everything under sanitizers on Linux

    docker run --rm -it --cap-add SYS_PTRACE -v "$PWD":/src:ro debian:trixie bash
    apt-get update && apt-get install -y build-essential clang libclang-rt-dev \
        libssl-dev openssl curl netcat-openbsd procps python3 slowhttptest
    cp -r /src /build && cd /build && make clean && make debug
    export ASAN_OPTIONS=abort_on_error=1:detect_leaks=0
    export UBSAN_OPTIONS=halt_on_error=1:abort_on_error=1
    sh test.sh ./pewter-debug && python3 conformance.py ./pewter-debug \
        && python3 fuzz.py ./pewter-debug
    make debug-tls
    sh test.sh ./pewter-debug && python3 conformance.py --tls ./pewter-debug \
        && python3 fuzz.py --tls ./pewter-debug

`detect_leaks=0` is required: LeakSanitizer reads `/proc` at exit, which does
not exist inside the chroot. The server never allocates on the request path
anyway. `slowhttptest -H/-B/-R/-X` and nikto have also been run against the
sanitizer build without findings; see the security model for the expected
behaviour under slow-connection attacks.

## Why root is required

pewter refuses to start unless it is root, because the two things that make it
safe to expose need root: `chroot(2)` into the document root, and dropping to an
unprivileged uid/gid afterwards. Running it as a normal user would silently
skip both, so it does not offer that mode.

## Security model

Startup, in this order, all before the first `accept()`:

1. Resolve the target user and group (needs `/etc/passwd`, so done pre-chroot).
2. Make sure fds 0, 1, 2 are open so a client socket can never land on them.
3. Bind and listen (this is what needs root for ports below 1024).
4. `chdir(docroot)`, then `chroot(".")`, then `chdir("/")`. Chrooting to the
   directory we are already in means there is no path re-resolution between
   check and use.
5. `setgroups`, `setgid`, `setuid`, then verify: `setuid(0)` and `setgid(0)`
   must fail and the real/effective ids must match. On Linux,
   `PR_SET_NO_NEW_PRIVS` is also set.

Per request, in a forked child:

- `alarm(timeout)` bounds the child's entire life; `SIGALRM` kills it.
  `SO_RCVTIMEO`/`SO_SNDTIMEO` are set as well.
- The request head is read into a fixed 8 KiB stack buffer. An over-long
  request line → 414, over-long headers → 431, a path segment longer than
  the filesystem allows → 414. Only `GET` and `HEAD` are
  served; the other RFC 9110 methods → 405, unknown tokens → 501.
- The header section is validated per RFC 9112 even though only three fields
  matter: a bare CR, obs-fold, whitespace before the colon, a non-token name
  or a control byte in a value → 400. HTTP/1.1 requires exactly one syntactic
  `Host`; `Content-Length` must be digits and consistent (over 7 digits →
  413, it will not be drained); `Transfer-Encoding` other than `chunked` →
  501, combined with `Content-Length` → 400. Request bodies are never read,
  only drained, so there is no smuggling surface.
- The target may be origin-form or absolute-form (`http://host/path`, which
  HTTP/1.1 servers must accept); the authority is validated and dropped. A
  fragment or a raw non-ASCII byte → 400. The path is percent-decoded, then
  rejected if it contains NUL or any control byte, a malformed escape, a `.`
  or `..` segment, or does not begin with `/`. Segments starting with `.`
  (dotfiles) answer 404. `//` collapses.
  The kernel's chroot is the real boundary; this is defense in depth.
- Only regular files are served; the target is opened with `O_NONBLOCK` so a
  FIFO in the document root cannot stall the child in `open()`. Directories
  redirect to the trailing-slash
  form and serve `index.html`; a directory without one answers 403. Listings
  are never generated.
- Every response carries `X-Content-Type-Options: nosniff` so browsers trust
  the extension-derived `Content-Type` rather than sniffing file contents.
- Error responses are a fixed `"<code> <reason>\n"` text body. Nothing from the
  request is ever echoed back, and the `Location` header on redirects is
  re-encoded from the sanitized path, so there is no injection surface.
- Each child serves exactly one request and sends `Connection: close`. After
  responding it drains leftover input briefly so the client sees the response
  rather than a TCP reset.
- Beyond `-c` concurrent children the parent answers 503 inline and closes.
- Log lines have control characters stripped from the request method and
  target, both length-capped, and each line is emitted with a single
  `write(2)` so concurrent children cannot interleave on a shared pipe.
- No heap allocation on the request path (the TLS library allocates for its
  own session state); no DNS, `syslog`, or locale after chroot (dates are
  UTC via `gmtime`).

### HTTPS

The TLS build keeps the same process model. The parent builds one
`SSL_CTX` before chroot: it loads the chain and key, requires TLS 1.2 or
newer, restricts TLS 1.2 to ECDHE with AES-GCM or ChaCha20-Poly1305,
disables compression, renegotiation, session caching and session tickets
(one request per connection and a fresh process per connection leave
nothing worth resuming), and seeds the random generator while the real
filesystem is still reachable. Every child inherits that context; it runs
the handshake on its socket, and from then on `read_request`, `send_head`
and the file loop go through `SSL_read`/`SSL_write` instead of the socket.
`sendfile(2)` is not used over TLS. The child sends `close_notify` before
the usual half-close and drain.

Consequences to know about:

- The private key lives in the memory of every child, which runs as
  `nobody` inside the chroot. That is the same exposure nginx or Apache
  workers have; a compromise of a child process exposes the key.
- A client that sends plain HTTP to the HTTPS port gets a plain-text
  `400 Bad Request` and a close, so the mistake is visible rather than a
  hang. The child peeks at the first byte before starting the handshake:
  TLS records start with a content-type byte, an HTTP method with a capital
  letter. Any other handshake failure is logged with the library's reason.
- The idle timeout and `SIGALRM` bound the handshake too, so a client that
  connects and sends nothing holds a child for at most `-t` seconds.
- When the `-c` limit is reached a plain-HTTP listener answers 503 inline
  from the parent; an HTTPS listener cannot without a handshake in the
  parent, so it just closes the connection.
- No `Strict-Transport-Security`, OCSP stapling, client certificates, ALPN
  or HTTP/2. Clients that offer ALPN fall back to HTTP/1.1.

### Non-goals

No keep-alive, Range requests, conditional requests (`If-Modified-Since`
always answers 200), directory listings, CGI, virtual hosts, compression,
HTTP/2 or certificate management (get certificates from certbot or similar
and restart to pick up a renewal). A reverse proxy (nginx, Caddy, haproxy)
remains a fine way to add any of those in front of the plain-HTTP build.

Symlinks inside the document root are followed; they cannot escape the chroot.

## sendfile

`send_file()` in `pewter.c` wraps the platform zero-copy call, hiding the three
different signatures:

| Platform | Call |
|----------|------|
| Linux    | `sendfile(out, in, &off, count)` from `<sys/sendfile.h>` |
| macOS    | `sendfile(in, out, off, &len, NULL, 0)` |
| FreeBSD  | `sendfile(in, out, off, nbytes, NULL, &sbytes, 0)` |

Partial transfers are resumed. If the call reports that it cannot handle the
descriptor pair or filesystem (`EINVAL`, `ENOSYS`, `ENOTSUP`, `EOPNOTSUPP`),
the wrapper continues from the current offset with a plain `read`/`write` loop.
Building with `-DPEWTER_NO_SENDFILE` uses that loop exclusively, and any other
platform gets it automatically.

## Portability notes

- Linux (glibc and musl), macOS and FreeBSD are the targets. Linux and macOS
  builds, including the test matrix, are exercised routinely; FreeBSD is
  written from the documented API and has not yet been run on real hardware.
- Feature-test macros are set per platform at the top of `pewter.c`; the
  Makefile has no platform logic at all.
- `build.zig` is Linux/musl only by design: it exists to produce static
  binaries, and it has been run through the full test matrix on aarch64
  with both the plain and the LibreSSL build, cross-compiled from macOS
  and built natively on Debian. The x86_64 binaries are built the same way
  but have only been compiled, not run.
