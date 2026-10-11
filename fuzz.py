#!/usr/bin/env python3
"""Network fuzzer for pewter: throws mutated and randomly generated HTTP
requests at a live server and checks that every reply is a well-formed
HTTP/1.1 response (or a clean close), that the parent survives, and that
the server log contains no sanitizer reports.

    sudo python3 fuzz.py [-p PORT] [-n CASES] [-j WORKERS] [--radamsa BIN] [-s SEED] path-to-pewter

Half of the cases come from radamsa (if found) mutating a seed corpus of
valid and edge-case requests; the rest come from a built-in structural
generator (random methods, targets, percent-escapes, versions, headers,
bodies, line endings).  A fifth of all cases are delivered in random
fragments with small delays to exercise partial reads.  Best run against a
`make debug` (ASan/UBSan) binary.  Must run as root (the server chroots).
"""
import argparse
import collections
import os
import random
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor

HOST = "127.0.0.1"

SEEDS = [
    b"GET / HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /index.html HTTP/1.1\r\nHost: 127.0.0.1:8080\r\nUser-Agent: fuzz\r\nAccept: */*\r\n\r\n",
    b"HEAD /big.bin HTTP/1.1\r\nHost: h\r\nConnection: close\r\n\r\n",
    b"GET /sub HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /sub/ HTTP/1.0\r\n\r\n",
    b"GET /a%20b.txt?x=1&y=%41 HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /%C3%A9.txt HTTP/1.1\r\nHost: [::1]:80\r\n\r\n",
    b"GET http://example.com/index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
    b"GET /../../etc/passwd HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /%2e%2e/%2e%2e/etc/passwd HTTP/1.1\r\nHost: h\r\n\r\n",
    b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
    b"GET / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc",
    b"GET /missing HTTP/1.1\r\nHost: h\r\nIf-Modified-Since: Tue, 15 Nov 1994 08:12:31 GMT\r\nRange: bytes=0-1\r\n\r\n",
    b"GET / HTTP/1.1\nHost: h\n\n",
    b"GET / HTTP/1.1\r\nHost: h\r\nX-A: foo\r\n bar\r\n\r\n",
    b"OPTIONS * HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /" + b"a" * 4000 + b" HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET / HTTP/1.1\r\nHost: h\r\n" + b"".join(b"X-%d: %d\r\n" % (i, i) for i in range(100)) + b"\r\n",
    b"GET /%00 HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /%zz%2 HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /.hidden HTTP/1.1\r\nHost: h\r\n\r\n",
    b"GET /sub/nodir/ HTTP/2.0\r\nHost: h\r\n\r\n",
    b"\r\nGET / HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nxx",
]

METHODS = [b"GET", b"HEAD", b"POST", b"PUT", b"OPTIONS", b"TRACE", b"CONNECT", b"BREW", b"get", b"G\x01T", b"", b"GET" * 50]
VERSIONS = [b"HTTP/1.1", b"HTTP/1.0", b"HTTP/1.5", b"HTTP/2.0", b"HTTP/1", b"HTTP/1.10", b"http/1.1", b"", b"HTTP/1.1 ", b"HTTP/9.9", b"HTTP/\xff.\xff"]
SEGS = [b"", b".", b"..", b"...", b"index.html", b"sub", b"nodir", b"big.bin", b"a%20b.txt", b"%2e%2e", b"%2E", b"%2F", b"%00",
        b"%", b"%2", b"%zz", b"%C3%A9", b"%c0%ae", b".hidden", b"link.html", b"a b", b"*", b"\\", b"..;", b"%5c..", b"\xff\xfe",
        b"\x7f", b"\x01", b"a" * 300, b"%41" * 200, b"?", b"#", b"&", b"=", b"~", b"@", b":", b"[", b"]", b"\"", b"<script>"]
HNAMES = [b"Host", b"host", b"HOST", b"Content-Length", b"Transfer-Encoding", b"Connection", b"Expect", b"Range", b"If-Modified-Since",
          b"X-A", b"X Y", b"", b"Host ", b"Content-Length", b"Transfer-Encoding", b"X-" + b"n" * 500, b"Host\x00", b"\xff"]
HVALS = [b"h", b"", b"127.0.0.1:8080", b"[::1]", b"a b", b"0", b"5", b"-1", b"abc", b"99999999999999999999999", b"chunked", b"gzip",
         b"chunked, gzip", b"close", b"keep-alive", b"100-continue", b"bytes=0-1", b"bytes=-1", b"\xe9", b"a\x01b", b"a\tb",
         b"a\rb", b"a" * 7000, b"0, 0", b"5, 6", b"\x00", b" \t ", b"%00", b"../../"]
EOLS = [b"\r\n", b"\r\n", b"\r\n", b"\n", b"\r", b"\r\r\n", b"\n\r"]


def gen_structural(rnd):
    r = rnd.random()
    if r < 0.03:
        return os.urandom(rnd.randint(0, 2000))
    if r < 0.06:
        return b"GET /" + os.urandom(rnd.randint(0, 200)) + b" HTTP/1.1\r\nHost: h\r\n\r\n"
    eol = rnd.choice(EOLS)
    method = rnd.choice(METHODS)
    if rnd.random() < 0.15:
        target = rnd.choice([b"*", b"http://h/", b"http://h", b"HTTP://[::1]:80/index.html", b"http:/x", b"//h/index.html",
                             b"index.html", b"", b"http://user:pw@h/", b"ftp://h/", b"http://" + b"h" * 5000 + b"/"])
    else:
        target = b"/" + b"/".join(rnd.choice(SEGS) for _ in range(rnd.randint(0, 6)))
        if rnd.random() < 0.3:
            target += b"/"
        if rnd.random() < 0.2:
            target += b"?" + rnd.choice(SEGS)
        if rnd.random() < 0.1:
            target += b"#" + rnd.choice(SEGS)
    sp = rnd.choice([b" ", b" ", b" ", b"  ", b"\t", b""])
    line = method + sp + target + sp + rnd.choice(VERSIONS)
    hdrs = []
    if rnd.random() < 0.8:
        hdrs.append(b"Host: h")
    for _ in range(rnd.randint(0, 12)):
        name = rnd.choice(HNAMES)
        val = rnd.choice(HVALS)
        colon = rnd.choice([b": ", b":", b" : ", b":\t", b""])
        h = name + colon + val
        if rnd.random() < 0.05:
            h = b" " + h            # obs-fold
        hdrs.append(h)
    rnd.shuffle(hdrs)
    msg = eol.join([line] + hdrs) + eol + eol
    if rnd.random() < 0.3:
        msg += os.urandom(rnd.randint(0, 3000))
    if rnd.random() < 0.05:
        msg = msg[: rnd.randint(0, len(msg))]      # truncated
    return msg


def radamsa_cases(radamsa, n, seed, workdir):
    seeddir = os.path.join(workdir, "seeds")
    outdir = os.path.join(workdir, "mut")
    os.makedirs(seeddir)
    os.makedirs(outdir)
    for i, s in enumerate(SEEDS):
        with open(os.path.join(seeddir, "s%02d" % i), "wb") as f:
            f.write(s)
    subprocess.check_call([radamsa, "-s", str(seed), "-n", str(n), "-o", os.path.join(outdir, "c-%n")]
                          + sorted(os.path.join(seeddir, f) for f in os.listdir(seeddir)))
    out = []
    for f in sorted(os.listdir(outdir)):
        with open(os.path.join(outdir, f), "rb") as fh:
            out.append(fh.read()[:65536])
    return out


# --------------------------------------------------------------------------

STATUS_RE = re.compile(rb"^HTTP/1\.1 (\d{3}) [^\r\n]*\r\n")


TLS = None                  # client SSLContext when running with --tls


def connect(port, timeout, plain=False):
    s = socket.create_connection((HOST, port), timeout=timeout)
    s.settimeout(timeout)
    if TLS is not None and not plain:
        s = TLS.wrap_socket(s, server_hostname="localhost")
    return s


def make_cert(d):
    cert, key = os.path.join(d, "cert.pem"), os.path.join(d, "key.pem")
    subprocess.check_call(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                           "-keyout", key, "-out", cert, "-subj", "/CN=localhost", "-days", "2"],
                          stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    return cert, key


def send_case(port, data, rnd, timeout=8.0):
    """Returns (status_code_or_label, anomaly_or_None)."""
    # With TLS, a tenth of the cases bypass the handshake and hit the
    # listener in the clear, which fuzzes SSL_accept with hostile bytes.
    plain = TLS is not None and rnd.random() < 0.1
    try:
        s = connect(port, timeout, plain)
    except (OSError, ssl.SSLError) as e:
        return "connect-failed", "connect failed: %s" % e
    try:
        try:
            if rnd.random() < 0.2 and len(data) > 1:
                i = 0
                while i < len(data):
                    k = rnd.randint(1, max(1, min(64, len(data) - i)))
                    s.sendall(data[i:i + k])
                    i += k
                    time.sleep(rnd.choice([0, 0, 0.001, 0.01]))
            else:
                s.sendall(data)
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            pass
        chunks = []
        closed = False
        total = 0
        try:
            while total < 64 * 1024 * 1024:
                d = s.recv(65536)
                if not d:
                    closed = True
                    break
                chunks.append(d)
                total += len(d)
        except socket.timeout:
            return "timeout", "no close within %ss" % timeout
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError):
            closed = True
    finally:
        s.close()
    raw = b"".join(chunks)
    if not raw:
        return "closed-silently", None
    if plain and raw[:2] == b"\x15\x03":
        return "tls-alert", None         # the library refused the handshake
    m = STATUS_RE.match(raw)
    if not m:
        return "garbage", "reply does not start with a status line: %r" % raw[:80]
    code = int(m.group(1))
    end = raw.find(b"\r\n\r\n")
    if end < 0:
        return code, "no end of headers: %r" % raw[:200]
    head = raw[:end]
    body = raw[end + 4:]
    cl = re.search(rb"\r\nContent-Length: (\d+)\r\n", head + b"\r\n")
    if cl is None:
        return code, "missing Content-Length: %r" % head[:200]
    if data.split(b" ", 1)[0] != b"HEAD" and int(cl.group(1)) != len(body):
        return code, "Content-Length %s != body %d" % (cl.group(1).decode(), len(body))
    if raw.count(b"\r\nHTTP/1.1 ") or raw.count(b"\r\n\r\nHTTP/1.1 "):
        pass
    return code, None


def build_docroot():
    root = tempfile.mkdtemp(prefix="pewter-fuzz.")
    os.makedirs(os.path.join(root, "sub", "nodir"))
    for name, content in (("index.html", b"<h1>root</h1>\n"), ("sub/index.html", b"<h1>sub</h1>\n"),
                          ("a b.txt", b"a b\n"), ("é.txt", b"e\n"), (".hidden", b"s\n"),
                          ("big.bin", os.urandom(1024 * 1024))):
        with open(os.path.join(root, name), "wb") as f:
            f.write(content)
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


def main():
    global TLS
    ap = argparse.ArgumentParser()
    ap.add_argument("binary")
    ap.add_argument("-p", "--port", type=int, default=8091)
    ap.add_argument("-n", "--cases", type=int, default=2000)
    ap.add_argument("-j", "--workers", type=int, default=8)
    ap.add_argument("-s", "--seed", type=int, default=1)
    ap.add_argument("--radamsa", default=shutil.which("radamsa"))
    ap.add_argument("--keep-cases", help="directory to save cases that produced anomalies")
    ap.add_argument("--tls", action="store_true", help="fuzz over HTTPS with a throwaway certificate")
    args = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("run as root (the server chroots)")
    binary = os.path.abspath(args.binary)
    rnd = random.Random(args.seed)

    work = tempfile.mkdtemp(prefix="pewter-fuzzwork.")
    cases = []
    if args.radamsa:
        cases += radamsa_cases(args.radamsa, args.cases // 2, args.seed, work)
        print("radamsa: %d cases from %d seeds" % (len(cases), len(SEEDS)))
    else:
        print("radamsa not found; structural cases only")
    while len(cases) < args.cases:
        cases.append(gen_structural(rnd))
    cases += SEEDS
    rnd.shuffle(cases)

    root = build_docroot()
    logpath = root + ".log"
    log = open(logpath, "w")
    argv = [binary, "-p", str(args.port), "-t", "5", "-c", str(args.workers * 4)]
    tls_dir = None
    if args.tls:
        tls_dir = tempfile.mkdtemp(prefix="pewter-tls.")
        cert, key = make_cert(tls_dir)
        argv += ["-C", cert, "-K", key]
        TLS = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        TLS.check_hostname = False
        TLS.verify_mode = ssl.CERT_NONE
    srv = subprocess.Popen(argv + [root], stderr=log, stdout=log)
    for _ in range(100):
        try:
            socket.create_connection((HOST, args.port), timeout=0.5).close()
            break
        except OSError:
            time.sleep(0.1)
    print("server pid %d; %d cases, %d workers%s" % (srv.pid, len(cases), args.workers, ", https" if args.tls else ""))

    hist = collections.Counter()
    anomalies = []
    t0 = time.time()

    def work_one(idx_case):
        idx, case = idx_case
        r = random.Random(args.seed * 1000003 + idx)
        code, anomaly = send_case(args.port, case, r)
        return idx, case, code, anomaly

    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        for idx, case, code, anomaly in ex.map(work_one, enumerate(cases)):
            hist[code] += 1
            if anomaly:
                anomalies.append((idx, case, anomaly))
            if idx % 500 == 499:
                print("  %d/%d  %.0f req/s" % (idx + 1, len(cases), (idx + 1) / (time.time() - t0)))

    alive = srv.poll() is None
    ok_after = False
    try:
        s = connect(args.port, 5)
        s.sendall(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n")
        ok_after = s.recv(100).startswith(b"HTTP/1.1 200")
        s.close()
    except (OSError, ssl.SSLError):
        pass
    srv.terminate()
    try:
        srv.wait(5)
    except subprocess.TimeoutExpired:
        srv.kill()
    log.close()
    with open(logpath, errors="replace") as f:
        logtext = f.read()
    san = [l for l in logtext.splitlines() if re.search(r"Sanitizer|runtime error|ERROR: |SUMMARY:", l)]

    print("--- outcomes (%.1fs):" % (time.time() - t0))
    for k, v in sorted(hist.items(), key=lambda kv: str(kv[0])):
        print("  %-16s %d" % (k, v))
    print("--- anomalies: %d" % len(anomalies))
    for idx, case, a in anomalies[:20]:
        print("  case %d: %s\n    %r" % (idx, a, case[:120]))
    if args.keep_cases and anomalies:
        os.makedirs(args.keep_cases, exist_ok=True)
        for idx, case, a in anomalies:
            with open(os.path.join(args.keep_cases, "anomaly-%d" % idx), "wb") as f:
                f.write(case)
    print("parent alive after fuzzing: %s; serves / afterwards: %s; exit status %s" % (alive, ok_after, srv.returncode))
    if san:
        print("--- SANITIZER REPORTS:")
        print(logtext[-6000:])
    shutil.rmtree(root, ignore_errors=True)
    shutil.rmtree(work, ignore_errors=True)
    if tls_dir:
        shutil.rmtree(tls_dir, ignore_errors=True)
    os.unlink(logpath)
    bad = (not alive) or (not ok_after) or anomalies or san or srv.returncode != 0
    print("=== fuzz %s" % ("FAIL" if bad else "ok"))
    sys.exit(1 if bad else 0)


if __name__ == "__main__":
    main()
