#!/usr/bin/env python3
"""HTTP/1.1 conformance suite for pewter (RFC 9110, RFC 9112, RFC 3986).

    sudo python3 conformance.py [-p PORT] [-t TIMEOUT] path-to-pewter

Builds a throwaway document root, starts the server on 127.0.0.1 and sends
raw requests over TCP, checking each response against the RFC text.  Every
check is tagged MUST (failure -> non-zero exit), SHOULD (reported, does not
fail the run) or NOTE (informational).  The server log is scanned for
AddressSanitizer / UBSan reports when the run ends, so pointing this at a
`make debug` binary turns it into a memory-safety test as well.

Only the Python standard library is used.  Must run as root because the
server chroots.
"""
import argparse
import email.utils
import hashlib
import os
import pwd
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time

HOST = "127.0.0.1"
PORT = 8090
SERVER_TIMEOUT = 3          # -t given to the server; the 408 check waits on it
READ_TIMEOUT = 6.0

results = {"MUST": [0, 0], "SHOULD": [0, 0], "NOTE": [0, 0]}
failures = []
TLS = None                  # client SSLContext when running with --tls


class Resp:
    def __init__(self, raw, closed):
        self.raw = raw
        self.closed = closed
        self.version = self.code = self.reason = None
        self.headers = []
        self.body = b""
        self.head_ok = False
        self.head = b""
        m = re.match(rb"^(HTTP/\d\.\d) (\d{3}) ([^\r\n]*)\r\n", raw)
        if not m:
            return
        self.version = m.group(1).decode()
        self.code = int(m.group(2))
        self.reason = m.group(3).decode("latin-1")
        end = raw.find(b"\r\n\r\n")
        if end < 0:
            return
        self.head = raw[: end + 4]
        self.body = raw[end + 4 :]
        self.head_ok = True
        for line in raw[m.end() : end].split(b"\r\n"):
            if b":" not in line:
                self.head_ok = False
                continue
            name, value = line.split(b":", 1)
            self.headers.append((name.decode("latin-1"), value.strip().decode("latin-1")))

    def get(self, name):
        return [v for n, v in self.headers if n.lower() == name.lower()]

    def one(self, name):
        vals = self.get(name)
        return vals[0] if len(vals) == 1 else None

    def __repr__(self):
        return "Resp(%r, closed=%r)" % (self.raw[:120], self.closed)


def tcp_connect(port, timeout=READ_TIMEOUT):
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    return s


def connect(port):
    s = tcp_connect(port)
    if TLS is not None:
        s = TLS.wrap_socket(s, server_hostname="localhost")
    return s


def make_cert(d):
    """Self-signed cert/key pair in directory d; returns (cert, key)."""
    cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    subprocess.check_call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                           "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "2"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def client_context(minimum=None, maximum=None):
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    if minimum is not None:
        ctx.minimum_version = minimum
    if maximum is not None:
        ctx.maximum_version = maximum
    return ctx


def read_all(s, limit=64 * 1024 * 1024):
    chunks = []
    total = 0
    closed = False
    try:
        while total < limit:
            d = s.recv(65536)
            if not d:
                closed = True
                break
            chunks.append(d)
            total += len(d)
    except socket.timeout:
        pass
    except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
        closed = True
    return b"".join(chunks), closed


def raw(port, data, half_close=False):
    """Send `data` (bytes or list of (bytes, delay) pieces) and read the reply."""
    s = connect(port)
    try:
        try:
            if isinstance(data, bytes):
                s.sendall(data)
            else:
                for piece, delay in data:
                    s.sendall(piece)
                    time.sleep(delay)
            if half_close:
                # Base-class call on purpose: SSLSocket.shutdown() would drop
                # the SSL object and later recv() would return ciphertext.
                socket.socket.shutdown(s, socket.SHUT_WR)
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            pass
        body, closed = read_all(s)
    finally:
        s.close()
    return Resp(body, closed)


def req(port, target="/", method="GET", version="HTTP/1.1", headers=None,
        host="h", body=b"", eol=b"\r\n"):
    lines = [b"%s %s %s" % (method.encode("latin-1"), target.encode("latin-1"),
                           version.encode("latin-1"))]
    if host is not None:
        lines.append(b"Host: " + host.encode("latin-1"))
    for h in headers or []:
        lines.append(h if isinstance(h, bytes) else h.encode("latin-1"))
    return eol.join(lines) + eol + eol + body


def check(level, name, cond, got="", ref=""):
    results[level][0 if cond else 1] += 1
    tag = "ok  " if cond else ("FAIL" if level == "MUST" else "warn")
    line = "  %s [%s] %s" % (tag, level, name)
    if not cond:
        line += "  (got: %s)" % (got,)
        if ref:
            line += "  [%s]" % ref
        failures.append((level, name, got, ref))
    print(line)


def imf_date(s):
    try:
        t = email.utils.parsedate_to_datetime(s)
    except (TypeError, ValueError, IndexError):
        return None
    if not re.match(r"^[A-Z][a-z]{2}, \d{2} [A-Z][a-z]{2} \d{4} \d{2}:\d{2}:\d{2} GMT$", s):
        return None
    return t.timestamp()


# --------------------------------------------------------------------------
# fixture and server
# --------------------------------------------------------------------------

def build_docroot():
    root = tempfile.mkdtemp(prefix="pewter-conf.")
    os.makedirs(os.path.join(root, "sub", "nodir"))
    with open(os.path.join(root, "index.html"), "w") as f:
        f.write("<!doctype html><h1>root</h1>\n")
    with open(os.path.join(root, "sub", "index.html"), "w") as f:
        f.write("<h1>sub</h1>\n")
    with open(os.path.join(root, "a b.txt"), "w") as f:
        f.write("a b\n")
    with open(os.path.join(root, "\u00e9.txt"), "w") as f:
        f.write("e-acute\n")
    with open(os.path.join(root, "data.JSON"), "w") as f:
        f.write("{}")
    with open(os.path.join(root, "noext"), "w") as f:
        f.write("x")
    with open(os.path.join(root, ".hidden"), "w") as f:
        f.write("secret\n")
    with open(os.path.join(root, "big.bin"), "wb") as f:
        f.write(os.urandom(2 * 1024 * 1024))
    os.symlink("index.html", os.path.join(root, "link.html"))
    os.chmod(root, 0o755)
    for dp, dn, fn in os.walk(root):
        for d in dn:
            os.chmod(os.path.join(dp, d), 0o755)
        for n in fn:
            p = os.path.join(dp, n)
            if not os.path.islink(p):
                os.chmod(p, 0o644)
    return root


def start_server(binary, port, root, log, tls_files=None):
    argv = [binary, "-p", str(port), "-t", str(SERVER_TIMEOUT), "-c", "32"]
    if tls_files:
        argv += ["-C", tls_files[0], "-K", tls_files[1]]
    p = subprocess.Popen(argv + [root], stderr=log, stdout=log)
    for _ in range(100):
        try:
            s = socket.create_connection((HOST, port), timeout=0.5)
            s.close()
            return p
        except OSError:
            if p.poll() is not None:
                raise SystemExit("server exited at startup, see log")
            time.sleep(0.1)
    raise SystemExit("server did not start listening")


# --------------------------------------------------------------------------
# checks
# --------------------------------------------------------------------------

def run_checks(port, root):
    R = lambda *a, **k: raw(port, req(port, *a, **k))

    print("--- message framing (RFC 9112 s.2, s.4, s.6)")
    r = R("/")
    check("MUST", "status line is HTTP/1.1 SP 3DIGIT SP reason CRLF", r.code == 200 and r.version == "HTTP/1.1", r)
    check("MUST", "header section ends with CRLFCRLF and every field line is name:value", r.head_ok, r.head[:200])
    check("MUST", "no bare LF in response head", b"\n" not in r.head.replace(b"\r\n", b""), r.head[:200])
    check("MUST", "no obs-fold in response head", not re.search(rb"\r\n[ \t]", r.head), r.head[:200])
    check("MUST", "field names are tokens (no space before colon)", all(re.match(r"^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$", n) for n, _ in r.headers), r.headers)
    check("MUST", "Content-Length equals body length", r.one("Content-Length") == str(len(r.body)), (r.one("Content-Length"), len(r.body)))
    check("MUST", "single Content-Length field", len(r.get("Content-Length")) == 1, r.get("Content-Length"))
    check("MUST", "no Transfer-Encoding in response (framed by Content-Length)", not r.get("Transfer-Encoding"), r.get("Transfer-Encoding"))
    check("MUST", "server closes the connection after the response", r.closed, r.closed, "RFC 9112 s.9.6")
    check("MUST", "Connection: close is sent when closing", (r.one("Connection") or "").lower() == "close", r.get("Connection"), "RFC 9112 s.9.6")
    d = r.one("Date")
    ts = imf_date(d) if d else None
    check("MUST", "Date header present (origin server with a clock)", d is not None, d, "RFC 9110 s.6.6.1")
    check("MUST", "Date is IMF-fixdate in GMT", ts is not None, d, "RFC 9110 s.5.6.7")
    check("SHOULD", "Date is within 5 minutes of now", ts is not None and abs(ts - time.time()) < 300, d)
    check("MUST", "Content-Type present with content", r.one("Content-Type") is not None, r.headers, "RFC 9110 s.8.3")
    check("NOTE", "reason phrase is the recommended one", r.reason == "OK", r.reason)
    check("NOTE", "Server header present", r.one("Server") is not None, r.headers)

    print("--- methods (RFC 9110 s.9, s.15.5.6)")
    g = R("/index.html")
    h = R("/index.html", method="HEAD")
    check("MUST", "GET returns 200 with body", g.code == 200 and len(g.body) > 0, g)
    check("MUST", "HEAD returns 200 with no body", h.code == 200 and h.body == b"" and h.closed, h)
    check("MUST", "HEAD Content-Length equals GET body length", h.one("Content-Length") == str(len(g.body)), (h.one("Content-Length"), len(g.body)), "RFC 9110 s.9.3.2")
    same = {n.lower(): v for n, v in g.headers if n.lower() != "date"} == {n.lower(): v for n, v in h.headers if n.lower() != "date"}
    check("SHOULD", "HEAD sends the same header fields as GET", same, (g.headers, h.headers), "RFC 9110 s.9.3.2")
    p = R("/", method="POST", headers=["Content-Length: 1"], body=b"x")
    check("MUST", "POST / -> 405", p.code == 405, p)
    allow = p.one("Allow") or ""
    check("MUST", "405 carries Allow", allow != "", p.headers, "RFC 9110 s.15.5.6")
    check("MUST", "Allow lists GET and HEAD", {t.strip() for t in allow.split(",")} >= {"GET", "HEAD"}, allow)
    for m in ("PUT", "DELETE", "PATCH"):
        x = R("/", method=m, headers=["Content-Length: 0"])
        check("MUST", "%s / -> 405 or 501" % m, x.code in (405, 501), x)
    x = R("*", method="OPTIONS")
    check("MUST", "OPTIONS * -> 200/204/405/501", x.code in (200, 204, 405, 501), x)
    x = R("/", method="TRACE", headers=["X-Secret: zzz"])
    check("MUST", "TRACE not reflected (no echo of request)", x.code in (405, 501) and b"zzz" not in x.body, x, "RFC 9110 s.9.3.8")
    x = R("host:80", method="CONNECT")
    check("MUST", "CONNECT -> 405/501, never 200", x.code in (400, 405, 501), x)
    x = R("/", method="get")
    check("MUST", "methods are case-sensitive: 'get' is not GET", x.code in (400, 405, 501), x, "RFC 9110 s.9.1")
    x = R("/", method="BREW")
    check("SHOULD", "unrecognized method -> 501", x.code == 501, x, "RFC 9110 s.9")
    x = R("/", method="GE\x01T")
    check("MUST", "method with CTL byte -> 400", x.code == 400, x, "RFC 9112 s.3")
    x = R("/index.html", headers=["Content-Length: 5"], body=b"hello")
    check("MUST", "GET with a body is served or rejected (200/400), never hangs", x.code in (200, 400) and x.closed, x, "RFC 9110 s.9.3.1")

    print("--- request line (RFC 9112 s.2.3, s.3)")
    x = R("/", version="HTTP/1.0", host=None)
    check("MUST", "HTTP/1.0 request without Host -> 200", x.code == 200, x)
    check("MUST", "HTTP/1.0 response is framed with Content-Length and closed", x.one("Content-Length") == str(len(x.body)) and x.closed, x)
    check("SHOULD", "responds HTTP/1.1 to an HTTP/1.0 request", x.version == "HTTP/1.1", x.version, "RFC 9112 s.2.3")
    x = R("/", host=None)
    check("MUST", "HTTP/1.1 request without Host -> 400", x.code == 400, x, "RFC 9112 s.3.2")
    x = R("/", headers=["Host: other"])
    check("MUST", "two Host fields -> 400", x.code == 400, x, "RFC 9112 s.3.2")
    x = R("/", host="")
    check("MUST", "empty Host value is accepted or 400", x.code in (200, 400), x, "RFC 9112 s.3.2")
    x = R("/", host="a b")
    check("MUST", "Host with invalid value (space) -> 400", x.code == 400, x, "RFC 9112 s.3.2")
    x = R("/", host="127.0.0.1:%d" % port)
    check("MUST", "Host with port accepted", x.code == 200, x)
    x = R("/", host="[::1]:80")
    check("MUST", "Host with IPv6 literal accepted", x.code == 200, x)
    x = raw(port, b"GET / HTTP/1.1\r\nhost: h\r\n\r\n")
    check("MUST", "field names are case-insensitive (host:)", x.code == 200, x, "RFC 9110 s.5.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHOST:h\r\n\r\n")
    check("MUST", "no space after colon accepted", x.code == 200, x, "RFC 9112 s.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost:\t h \t\r\n\r\n")
    check("MUST", "OWS around field value accepted", x.code == 200, x, "RFC 9112 s.5")
    x = R("/", version="HTTP/1.5")
    check("SHOULD", "HTTP/1.x with higher minor is processed as HTTP/1.1", x.code == 200, x, "RFC 9112 s.2.3")
    for v in ("HTTP/2.0", "HTTP/3.0", "HTTP/9.9"):
        x = R("/", version=v)
        check("MUST", "%s -> 505" % v, x.code == 505, x, "RFC 9110 s.15.6.6")
    for v in ("HTTP/1.10", "HTTP/01.1", "http/1.1", "HTTP/1", "HTTP/1.", "HTTP1.1", "HTTP/1.1 ", "FTP/1.0"):
        x = raw(port, b"GET / " + v.encode() + b"\r\nHost: h\r\n\r\n")
        check("MUST", "malformed version %r -> 400" % v, x.code == 400, x, "RFC 9112 s.2.3")
    x = raw(port, b"GET /\r\nHost: h\r\n\r\n")
    check("MUST", "HTTP/0.9 style request line -> 400", x.code == 400, x)
    x = raw(port, b"GET  / HTTP/1.1\r\nHost: h\r\n\r\n")
    check("SHOULD", "two spaces in request line -> 400", x.code == 400, x, "RFC 9112 s.3")
    x = raw(port, b"GET\t/\tHTTP/1.1\r\nHost: h\r\n\r\n")
    check("SHOULD", "tabs instead of SP in request line -> 400", x.code == 400, x, "RFC 9112 s.3")
    x = raw(port, b"GET / HTTP/1.1 \r\nHost: h\r\n\r\n")
    check("SHOULD", "trailing whitespace after version -> 400", x.code == 400, x, "RFC 9112 s.3")
    x = raw(port, b" GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    check("SHOULD", "leading whitespace before method -> 400", x.code == 400, x, "RFC 9112 s.2.2")
    x = raw(port, b"\r\nGET / HTTP/1.1\r\nHost: h\r\n\r\n")
    check("SHOULD", "leading empty line before request line is ignored", x.code == 200, x, "RFC 9112 s.2.2")
    x = raw(port, b"GET / HTTP/1.1\rHost: h\r\n\r\n")
    check("MUST", "bare CR in request line -> 400", x.code == 400, x, "RFC 9112 s.2.2")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\rX: y\r\n\r\n")
    check("MUST", "bare CR inside a field line -> 400", x.code == 400, x, "RFC 9112 s.2.2")
    x = raw(port, b"GET / HTTP/1.1\nHost: h\n\n")
    check("NOTE", "bare LF line endings accepted (MAY)", x.code == 200, x, "RFC 9112 s.2.2")
    x = raw(port, b"GET http://127.0.0.1:%d/index.html HTTP/1.1\r\nHost: h\r\n\r\n" % port)
    check("MUST", "absolute-form request-target accepted", x.code == 200, x, "RFC 9112 s.3.2.2")
    x = raw(port, b"GET HTTP://example.com/sub/ HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "absolute-form with uppercase scheme accepted", x.code == 200, x, "RFC 9110 s.4.2.3")
    x = raw(port, b"GET https://example.com/index.html?q=1 HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "absolute-form https with query accepted", x.code == 200, x, "RFC 9112 s.3.2.2")
    x = raw(port, b"GET http://example.com HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "absolute-form with empty path -> / (200) or 400", x.code in (200, 400), x, "RFC 9112 s.3.2.2")
    x = raw(port, b"GET http://user@example.com/ HTTP/1.1\r\nHost: h\r\n\r\n")
    check("NOTE", "absolute-form with userinfo is 200 or 400", x.code in (200, 400), x, "RFC 9110 s.4.2.4")
    x = raw(port, b"GET http://example.com/../index.html HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "absolute-form dot-segments rejected (400/404)", x.code in (400, 404), x)
    x = raw(port, b"GET http:/x HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "malformed absolute-form -> 400", x.code == 400, x)
    x = raw(port, b"GET * HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "asterisk-form with GET -> 400", x.code == 400, x, "RFC 9112 s.3.2.4")
    x = raw(port, b"GET index.html HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "relative request-target -> 400", x.code == 400, x, "RFC 9112 s.3.2.1")
    x = raw(port, b"GET /#frag HTTP/1.1\r\nHost: h\r\n\r\n")
    check("SHOULD", "fragment in request-target -> 400", x.code == 400, x, "RFC 9112 s.3.2")
    x = raw(port, b"GET /a b.txt HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "raw space in request-target -> 400", x.code == 400, x, "RFC 9112 s.3")
    x = raw(port, b"GET /\x01 HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "CTL byte in request-target -> 400", x.code == 400, x)
    x = raw(port, b"GET /\xc3\xa9.txt HTTP/1.1\r\nHost: h\r\n\r\n")
    check("SHOULD", "raw non-ASCII in request-target -> 400", x.code == 400, x, "RFC 3986 s.2")
    x = raw(port, b"GET /%C3%A9.txt HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "percent-encoded UTF-8 name is decoded and served", x.code == 200 and x.body == b"e-acute\n", x)
    x = raw(port, b'GET /<>"{}|\\^`[] HTTP/1.1\r\nHost: h\r\n\r\n')
    check("NOTE", "raw chars outside pchar (<>\"{}|\\^`[]) are rejected", x.code == 400, x, "RFC 3986 s.3.3")
    x = raw(port, b"GET /" + b"a" * 10000 + b" HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "request-target longer than the server accepts -> 414", x.code == 414, x, "RFC 9112 s.3")
    x = raw(port, b"GET /" + b"a" * 5000 + b" HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "5000-byte request-target -> 414 or 404", x.code in (404, 414), x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX: " + b"a" * 10000 + b"\r\n\r\n")
    check("MUST", "header section too large -> 431 (or 400)", x.code in (431, 400), x, "RFC 6585 s.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX: " + b"a" * 6000 + b"\r\n\r\n")
    check("MUST", "6000-byte header value within limits -> 200", x.code == 200, x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\n" + b"".join(b"X-%d: v\r\n" % i for i in range(300)) + b"\r\n")
    check("MUST", "300 small header fields -> 200", x.code == 200, x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\n" + b"X" * 1000 + b": v\r\n\r\n")
    check("MUST", "1000-byte field name -> 200", x.code == 200, x)

    print("--- header field syntax (RFC 9112 s.5, s.6)")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX-A: foo\r\n bar\r\n\r\n")
    check("MUST", "obs-fold (continuation line) -> 400 or treated as SP", x.code in (200, 400), x, "RFC 9112 s.5.2")
    check("SHOULD", "obs-fold rejected with 400", x.code == 400, x, "RFC 9112 s.5.2")
    x = raw(port, b"GET / HTTP/1.1\r\nHost : h\r\n\r\n")
    check("MUST", "whitespace between field name and colon -> 400", x.code == 400, x, "RFC 9112 s.5.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX Y: z\r\n\r\n")
    check("MUST", "space inside field name -> 400", x.code == 400, x, "RFC 9112 s.5.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\n: z\r\n\r\n")
    check("MUST", "empty field name -> 400", x.code == 400, x, "RFC 9112 s.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nnocolon\r\n\r\n")
    check("SHOULD", "field line without colon -> 400", x.code == 400, x, "RFC 9112 s.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX-A: caf\xe9\r\n\r\n")
    check("MUST", "obs-text (0x80-0xFF) in a field value accepted", x.code == 200, x, "RFC 9110 s.5.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX-A: a\x01b\r\n\r\n")
    check("SHOULD", "CTL byte in a field value -> 400", x.code == 400, x, "RFC 9110 s.5.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX-A: a\tb\r\n\r\n")
    check("MUST", "HTAB inside a field value accepted", x.code == 200, x, "RFC 9110 s.5.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX-A:\r\n\r\n")
    check("MUST", "empty field value accepted", x.code == 200, x, "RFC 9110 s.5.5")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX-A: a\x00b\r\n\r\n")
    check("MUST", "NUL byte in the head -> 400", x.code == 400, x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: abc\r\n\r\n")
    check("MUST", "invalid Content-Length -> 400", x.code == 400, x, "RFC 9112 s.6.3")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: -1\r\n\r\n")
    check("MUST", "negative Content-Length -> 400", x.code == 400, x, "RFC 9112 s.6.3")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\n")
    check("MUST", "differing Content-Length fields -> 400", x.code == 400, x, "RFC 9112 s.6.3")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 0, 0\r\n\r\n")
    check("MUST", "Content-Length list of identical values -> 200 or 400", x.code in (200, 400), x, "RFC 9112 s.6.3")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 99999999999999999999999\r\n\r\n")
    check("MUST", "overflowing Content-Length -> 400 or 413, no crash", x.code in (400, 413), x, "RFC 9112 s.6.3")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
    check("MUST", "chunked GET body -> 200 or 400, never hangs", x.code in (200, 400) and x.closed, x, "RFC 9112 s.6.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\n")
    check("SHOULD", "unknown transfer coding -> 501", x.code == 501, x, "RFC 9112 s.6.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nContent-Length: 3\r\n\r\n0\r\n\r\n")
    check("MUST", "Transfer-Encoding with Content-Length -> 400 or served then closed", x.code in (200, 400) and x.closed, x, "RFC 9112 s.6.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n")
    check("MUST", "Expect: 100-continue gets a final status (200/417) without waiting for the body", x.code in (200, 417), x, "RFC 9110 s.10.1.1")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nConnection: keep-alive\r\n\r\n")
    check("MUST", "keep-alive request still answered with close and closed", x.code == 200 and (x.one("Connection") or "").lower() == "close" and x.closed, x, "RFC 9112 s.9.6")
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\n\r\nGET /missing HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "pipelined second request not answered after close", x.code == 200 and x.raw.count(b"HTTP/1.1 ") == 1, x.raw.count(b"HTTP/1.1 "), "RFC 9112 s.9.3.2")
    x = raw(port, b"GET /index.html HTTP/1.1\r\nHost: h\r\nContent-Length: 1048576\r\n\r\n" + b"z" * 1048576)
    check("MUST", "1 MiB request body on GET is drained or rejected; response delivered", x.code in (200, 400, 413) and x.closed, x)

    print("--- incremental delivery")
    x = raw(port, [(bytes([c]), 0.01) for c in b"GET /index.html HTTP/1.1\r\nHost: h\r\n\r\n"])
    check("MUST", "byte-at-a-time request -> 200", x.code == 200, x)
    x = raw(port, [(b"GET / HTTP/1.1\r\nHost: h\r\n", 0.3), (b"\r\n", 0)])
    check("MUST", "head split before the final CRLF -> 200", x.code == 200, x)
    x = raw(port, [(b"GET / HTTP/1.1\r\nHost: h\r\n\r", 0.3), (b"\n", 0)])
    check("MUST", "head split between CR and LF -> 200", x.code == 200, x)
    x = raw(port, [(b"GET / HTTP/1.1\r\nHost: h\r", 0.3), (b"\n\r\n", 0)])
    check("MUST", "head split after a CR -> 200", x.code == 200, x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", half_close=True)
    check("MUST", "client half-close after request still served", x.code == 200, x)
    x = raw(port, b"", half_close=True)
    check("MUST", "client closes without sending: no reply or 400, connection closed", (x.code in (None, 400)) and x.closed, x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\nX: ", half_close=True)
    check("MUST", "client closes mid-head: 400 or close", (x.code in (None, 400)) and x.closed, x)
    t0 = time.time()
    s = connect(port)
    s.settimeout(SERVER_TIMEOUT + 4)
    s.sendall(b"GET / HTTP/1.1\r\nHost: h\r\n")
    body, closed = read_all(s)
    s.close()
    el = time.time() - t0
    x = Resp(body, closed)
    check("MUST", "idle incomplete request times out (408 or close) within -t + 2s", closed and el < SERVER_TIMEOUT + 2 and x.code in (None, 408), (x.code, round(el, 1), closed), "RFC 9110 s.15.5.9")

    print("--- response semantics (RFC 9110 s.8, s.13, s.14, s.15)")
    x = R("/missing")
    check("MUST", "404 for a missing file with explanatory body", x.code == 404 and len(x.body) > 0, x)
    check("MUST", "404 body matches Content-Length and is text/plain or html", x.one("Content-Length") == str(len(x.body)) and (x.one("Content-Type") or "").startswith("text/"), x)
    h = R("/missing", method="HEAD")
    check("MUST", "HEAD on 404: no body, same Content-Length", h.code == 404 and h.body == b"" and h.one("Content-Length") == str(len(x.body)), h)
    x = R("/sub")
    check("MUST", "directory without trailing slash -> 301", x.code == 301, x)
    check("MUST", "301 has a Location", x.one("Location") is not None, x.headers, "RFC 9110 s.10.2.2")
    check("MUST", "Location is /sub/ (absolute-path reference)", x.one("Location") == "/sub/", x.one("Location"), "RFC 9110 s.10.2.2")
    h = R("/sub", method="HEAD")
    check("MUST", "HEAD on 301: Location present, no body", h.code == 301 and h.one("Location") == "/sub/" and h.body == b"", h)
    x = R("/sub?x=1")
    check("NOTE", "301 Location preserves the query string", x.one("Location") == "/sub/?x=1", x.one("Location"))
    x = R("/a%20b")
    check("MUST", "301 Location is percent-encoded for a space-containing dir (404 here, no such dir)", x.code == 404, x)
    x = R("/sub/nodir/")
    check("MUST", "directory without index -> 403 (no listing)", x.code == 403, x)
    x = R("/.hidden")
    check("MUST", "dotfile -> 404", x.code == 404, x)
    x = R("/noext")
    check("MUST", "unknown extension -> application/octet-stream", x.code == 200 and x.one("Content-Type") == "application/octet-stream", x.one("Content-Type"))
    x = R("/index.html")
    check("MUST", "text/html gets charset parameter", x.one("Content-Type") == "text/html; charset=utf-8", x.one("Content-Type"), "RFC 9110 s.8.3.1")
    x = R("/data.JSON")
    check("SHOULD", "extension match is case-insensitive", x.one("Content-Type") == "application/json", x.one("Content-Type"))
    lm = R("/index.html").one("Last-Modified")
    lmt = imf_date(lm) if lm else None
    check("SHOULD", "Last-Modified present on 200", lm is not None, lm, "RFC 9110 s.8.8.2")
    check("MUST", "Last-Modified is IMF-fixdate and not in the future", lmt is not None and lmt <= time.time() + 1, lm, "RFC 9110 s.8.8.2")
    x = R("/index.html", headers=["If-Modified-Since: " + email.utils.formatdate(time.time() + 3600, usegmt=True)])
    check("NOTE", "If-Modified-Since newer than file -> 304", x.code == 304, x.code, "RFC 9110 s.13.1.3")
    x = R("/index.html", headers=["If-Modified-Since: garbage"])
    check("MUST", "invalid If-Modified-Since is ignored (200)", x.code == 200, x, "RFC 9110 s.13.1.3")
    x = R("/index.html", headers=["If-None-Match: \"abc\""])
    check("MUST", "If-None-Match without ETag support -> 200", x.code == 200, x)
    big = R("/big.bin")
    with open(os.path.join(root, "big.bin"), "rb") as f:
        want = f.read()
    check("MUST", "2 MiB file: Content-Length equals size and body is byte-exact", big.code == 200 and big.one("Content-Length") == str(len(want)) and hashlib.sha256(big.body).digest() == hashlib.sha256(want).digest(), (big.one("Content-Length"), len(big.body)))
    x = R("/big.bin", headers=["Range: bytes=0-9"])
    check("MUST", "Range ignored -> 200 with full body (no partial support)", x.code == 200 and len(x.body) == len(want) and not x.get("Content-Range"), (x.code, len(x.body)))
    check("MUST", "no Accept-Ranges: bytes when ranges unsupported", (x.one("Accept-Ranges") or "none") in ("none",), x.get("Accept-Ranges"), "RFC 9110 s.14.3")
    x = R("/?a=1&b=2")
    check("MUST", "query string ignored for static file", x.code == 200, x)
    x = R("/?")
    check("MUST", "empty query accepted", x.code == 200, x)
    x = R("/index%2Ehtml")
    check("MUST", "percent-encoded unreserved char is equivalent (%2E)", x.code == 200, x, "RFC 3986 s.2.3")
    x = R("/%69ndex.html")
    check("MUST", "percent-encoded letter decoded (%69 -> i)", x.code == 200, x, "RFC 3986 s.2.3")
    x = R("/a+b.txt")
    check("MUST", "'+' is literal in a path (not space)", x.code == 404, x, "RFC 3986")
    x = R("/A%20B.TXT")
    check("NOTE", "paths are case-sensitive", x.code == 404, x)
    x = R("/link.html")
    check("NOTE", "symlink inside docroot is followed", x.code == 200, x)
    x = raw(port, b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "error and success responses never echo request data", b"Host" not in R("/" + "q" * 50 + "?echo=<script>").body, "")

    print("--- path traversal and normalization (security)")
    for t in ("/../etc/passwd", "/..", "/../", "/sub/../index.html", "/sub/..", "/./index.html", "/.",
              "/%2e%2e/etc/passwd", "/%2E%2E/", "/sub/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2fetc/passwd",
              "/%2e/index.html", "/.%2e/", "/sub/..;/index.html", "/index.html/../index.html", "//../etc/passwd",
              "/%2e%2e%5cetc/passwd", "/....//etc/passwd", "/%252e%252e/etc/passwd", "/%c0%ae%c0%ae/etc/passwd",
              "/%00", "/index.html%00.txt", "/%2500", "/%", "/%2", "/%zz", "/%g1", "/a%0d%0ab", "/\\index.html",
              "/sub\\..\\index.html", "/%5c..%5c..%5cetc/passwd", "/etc/passwd", "/.hidden/../index.html",
              "/.git/config", "/.%2e", "/%2e", "/index.html/", "/index.html/.", "/sub/index.html/..", "/..\\"):
        x = R(t)
        check("MUST", "traversal attempt %r never yields 200 or 5xx" % t, x.code in (400, 403, 404), x)
    x = R("//index.html")
    check("NOTE", "double slash collapses (//index.html -> 200)", x.code == 200, x)
    x = R("/sub%2Findex.html")
    check("NOTE", "%2F is treated as a separator (200) or literal (404)", x.code in (200, 404), x)
    x = raw(port, b"GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: h\r\n\r\n")
    check("MUST", "deep encoded traversal never returns passwd content", b"root:" not in x.body, x)


def run_tls_checks(port):
    print("--- TLS (RFC 9110 s.4.2.2, RFC 8446, RFC 9325)")
    s = connect(port)
    ver, cipher = s.version(), s.cipher()[0]
    s.close()
    check("MUST", "negotiates TLS 1.2 or 1.3", ver in ("TLSv1.2", "TLSv1.3"), ver, "RFC 9325 s.3.1.1")
    check("MUST", "cipher suite is AEAD with forward secrecy", ver == "TLSv1.3" or ("ECDHE" in cipher and ("GCM" in cipher or "CHACHA20" in cipher)), cipher, "RFC 9325 s.4.2")
    for name, vmax in (("TLS 1.0", ssl.TLSVersion.TLSv1), ("TLS 1.1", ssl.TLSVersion.TLSv1_1)):
        accepted = False
        try:
            ctx = client_context(ssl.TLSVersion.TLSv1, vmax)
            ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
            c = ctx.wrap_socket(tcp_connect(port), server_hostname="localhost")
            accepted = c.version() is not None
            c.close()
        except (ssl.SSLError, OSError, ValueError):
            pass
        check("MUST", "%s refused" % name, not accepted, accepted, "RFC 8996")
    # plain HTTP on the HTTPS port: a clean 400 in the clear, then close
    s = tcp_connect(port)
    s.sendall(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    body, closed = read_all(s)
    s.close()
    x = Resp(body, closed)
    check("SHOULD", "plain HTTP on the HTTPS port -> 400 in the clear, connection closed", x.code == 400 and closed, x)
    # garbage at handshake time: no reply we can parse as HTTP, connection closed
    s = tcp_connect(port)
    s.sendall(b"\x16\x03\x01\x00\x05\x01\x00\x00\x01\x00")
    body, closed = read_all(s)
    s.close()
    check("MUST", "malformed ClientHello: connection closed", closed, (body[:40], closed))
    # a client that completes the handshake and then sends nothing
    t0 = time.time()
    s = connect(port)
    s.settimeout(SERVER_TIMEOUT + 4)
    body, closed = read_all(s)
    s.close()
    check("MUST", "idle TLS client dropped within -t + 2s", closed and time.time() - t0 < SERVER_TIMEOUT + 2, (round(time.time() - t0, 1), closed))
    # close_notify: Python reports a clean EOF (b"") only if the server shut down the session
    s = connect(port)
    s.sendall(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
    got_eof = False
    try:
        while True:
            d = s.recv(65536)
            if not d:
                got_eof = True
                break
    except ssl.SSLError:
        got_eof = False
    s.close()
    check("SHOULD", "server sends close_notify before closing", got_eof, got_eof, "RFC 8446 s.6.1")


# --------------------------------------------------------------------------

def main():
    global SERVER_TIMEOUT, TLS
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("-p", "--port", type=int, default=PORT)
    ap.add_argument("-t", "--timeout", type=int, default=SERVER_TIMEOUT)
    ap.add_argument("--tls", action="store_true",
                    help="run everything over HTTPS with a throwaway self-signed certificate")
    args = ap.parse_args()
    SERVER_TIMEOUT = args.timeout
    if os.geteuid() != 0:
        sys.exit("run as root (the server chroots)")
    binary = os.path.abspath(args.binary)
    if not os.access(binary, os.X_OK):
        sys.exit("no executable at %s" % binary)
    try:
        pwd.getpwnam("nobody")
    except KeyError:
        sys.exit("user nobody missing")

    root = build_docroot()
    logpath = root + ".log"
    log = open(logpath, "w")
    tls_files = None
    tls_dir = None
    if args.tls:
        tls_dir = tempfile.mkdtemp(prefix="pewter-tls.")
        tls_files = make_cert(tls_dir)
        TLS = client_context()
    srv = start_server(binary, args.port, root, log, tls_files)
    print("server pid %d, docroot %s%s" % (srv.pid, root, ", https" if args.tls else ""))
    try:
        run_checks(args.port, root)
        if args.tls:
            run_tls_checks(args.port)
    finally:
        srv.terminate()
        try:
            srv.wait(5)
        except subprocess.TimeoutExpired:
            srv.kill()
        log.close()

    with open(logpath, "r", errors="replace") as f:
        logtext = f.read()
    san = [l for l in logtext.splitlines() if re.search(r"Sanitizer|runtime error|ERROR: |SUMMARY:", l)]
    check("MUST", "no sanitizer reports in the server log", not san, san[:5])
    check("MUST", "server exited cleanly on SIGTERM", srv.returncode == 0, srv.returncode)
    if san:
        print("--- sanitizer output:")
        print(logtext[-4000:])
    shutil.rmtree(root, ignore_errors=True)
    if tls_dir:
        shutil.rmtree(tls_dir, ignore_errors=True)
    os.unlink(logpath)

    print("=== MUST pass=%d fail=%d | SHOULD pass=%d fail=%d | NOTE pass=%d fail=%d" % (
        results["MUST"][0], results["MUST"][1], results["SHOULD"][0], results["SHOULD"][1],
        results["NOTE"][0], results["NOTE"][1]))
    if failures:
        print("--- failures:")
        for lvl, name, got, ref in failures:
            print("  %-6s %s  (got: %s) %s" % (lvl, name, got, ("[" + ref + "]") if ref else ""))
    sys.exit(1 if results["MUST"][1] else 0)


if __name__ == "__main__":
    main()
