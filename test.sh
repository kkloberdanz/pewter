#!/bin/sh
# End-to-end test matrix for pewter.  Must run as root (the server chroots).
#
#   sudo sh test.sh [path-to-pewter] [port]
#
# Builds a throwaway document root under mktemp, starts the server on
# 127.0.0.1, runs ~50 curl/nc checks (status codes, headers, traversal
# attempts, malformed requests, 20 MB transfer integrity, slowloris
# timeout, connection limit, privilege drop) and exits non-zero on failure.
# A TLS-capable binary (make tls) additionally gets an HTTPS section on
# port+1 with a throwaway self-signed certificate.
# Needs: curl, nc, pgrep, shasum or sha256sum; openssl for the TLS section.

BIN=${1:-./pewter}; PORT=${2:-8089}
case "$BIN" in /*) ;; *) BIN="$(pwd)/$BIN" ;; esac
[ "$(id -u)" = 0 ] || { echo "run as root (sudo sh test.sh)"; exit 2; }
[ -x "$BIN" ] || { echo "no binary at $BIN (run make first)"; exit 2; }

ROOT=$(mktemp -d "${TMPDIR:-/tmp}/pewter-test.XXXXXX") || exit 2
trap 'rm -rf "$ROOT" "$ROOT.log" "$ROOT.dl" "$ROOT.tls" "$ROOT.tlslog"' EXIT
mkdir -p "$ROOT/sub/nodir" "$ROOT/dirdotindex/index.html"
printf '<!doctype html><h1>root</h1>\n' > "$ROOT/index.html"
printf '<h1>sub</h1>\n' > "$ROOT/sub/index.html"
printf 'a b\n' > "$ROOT/a b.txt"
printf 'secret\n' > "$ROOT/.hidden"
printf 'x' > "$ROOT/noext"; chmod 000 "$ROOT/noext"
printf '{}' > "$ROOT/data.JSON"
head -c 20971520 /dev/urandom > "$ROOT/big.bin"
ln -s index.html "$ROOT/link.html"
chmod 755 "$ROOT"

U=http://127.0.0.1:$PORT
fail=0; pass=0
ok()   { pass=$((pass+1)); echo "  ok   $1"; }
bad()  { fail=$((fail+1)); echo "  FAIL $1 (got: $2)"; }
code() { curl -s -o /dev/null -w '%{http_code}' --max-time 10 "$@"; }
expect() { # expect <code> <desc> curl-args...
    want=$1; desc=$2; shift 2
    got=$(code "$@"); [ "$got" = "$want" ] && ok "$desc -> $want" || bad "$desc expected $want" "$got"
}
have() { command -v "$1" >/dev/null 2>&1; }
sha() { if have sha256sum; then sha256sum "$1" | cut -c1-64; else shasum -a 256 "$1" | cut -c1-64; fi; }

"$BIN" -p "$PORT" -t 4 -c 3 "$ROOT" 2>"$ROOT.log" &
SPID=$!
i=0; until code "$U/" >/dev/null 2>&1 || [ $i -ge 50 ]; do i=$((i+1)); sleep 0.1; done
echo "server pid $SPID"

expect 200 "GET /"                 "$U/"
expect 200 "HEAD /"                -I "$U/"
expect 200 "GET /index.html"       "$U/index.html"
expect 200 "GET /sub/"             "$U/sub/"
expect 301 "GET /sub (no slash)"   "$U/sub"
expect 200 "GET /sub -L follows"   -L "$U/sub"
expect 403 "GET /sub/nodir/"       "$U/sub/nodir/"
expect 301 "GET /sub/nodir (dir, no slash)" "$U/sub/nodir"
expect 403 "GET /dirdotindex/"     "$U/dirdotindex/"
expect 404 "GET /.hidden"          "$U/.hidden"
expect 404 "GET /missing"          "$U/missing"
expect 404 "GET /index.html/x"     "$U/index.html/x"
expect 200 "GET /a%20b.txt"        "$U/a%20b.txt"
expect 200 "GET /link.html"        "$U/link.html"
expect 403 "GET /noext (mode 000)" "$U/noext"
expect 200 "GET /?query#frag"      "$U/?x=1"
expect 400 "GET /../etc/passwd"    --path-as-is "$U/../etc/passwd"
expect 400 "GET /%2e%2e/etc/passwd" --path-as-is "$U/%2e%2e/etc/passwd"
expect 400 "GET /sub/./x"          --path-as-is "$U/sub/./x"
expect 400 "GET /%00"              --path-as-is "$U/%00"
expect 400 "GET /%zz"              --path-as-is "$U/%zz"
expect 400 "GET /a%0d%0ab"         --path-as-is "$U/a%0d%0ab"
expect 405 "POST /"                -X POST "$U/"
expect 405 "PUT /"                 -X PUT -d x "$U/"
expect 200 "big.bin status"        "$U/big.bin"
seg=$(awk 'BEGIN{for(i=0;i<300;i++)printf "n"}')
expect 414 "300-char path segment"  "$U/$seg"

# content checks
ct=$(curl -sI "$U/" | tr -d '\r' | grep -i '^content-type:' | cut -d' ' -f2-)
[ "$ct" = "text/html; charset=utf-8" ] && ok "content-type html" || bad "content-type html" "$ct"
ct=$(curl -sI "$U/data.JSON" | tr -d '\r' | grep -i '^content-type:' | cut -d' ' -f2-)
[ "$ct" = "application/json" ] && ok "content-type case-insensitive ext" || bad "content-type json" "$ct"
loc=$(curl -sI "$U/sub" | tr -d '\r' | grep -i '^location:' | cut -d' ' -f2-)
[ "$loc" = "/sub/" ] && ok "301 Location /sub/" || bad "301 Location" "$loc"
cl=$(curl -sI "$U/big.bin" | tr -d '\r' | grep -i '^content-length:' | cut -d' ' -f2-)
[ "$cl" = "20971520" ] && ok "content-length big.bin" || bad "content-length big.bin" "$cl"
body=$(curl -s "$U/missing"); [ "$body" = "404 Not Found" ] && ok "error body fixed text" || bad "error body" "$body"
hb=$(curl -s -I "$U/big.bin" | wc -c); [ "$hb" -lt 400 ] && ok "HEAD sends no body" || bad "HEAD body" "$hb"
lm=$(curl -sI "$U/" | tr -d '\r' | grep -ic '^last-modified:'); [ "$lm" = 1 ] && ok "Last-Modified present" || bad "Last-Modified" "$lm"
conn=$(curl -sI "$U/" | tr -d '\r' | grep -i '^connection:' | cut -d' ' -f2-); [ "$conn" = "close" ] && ok "Connection: close" || bad "Connection" "$conn"

# large transfer integrity (sendfile loop)
curl -s -o "$ROOT.dl" "$U/big.bin"
[ "$(sha "$ROOT/big.bin")" = "$(sha "$ROOT.dl")" ] && ok "big.bin sha256 matches" || bad "big.bin sha256" "mismatch"
rm -f "$ROOT.dl"

# raw protocol edge cases
raw() { printf "$1" | nc -w 3 127.0.0.1 "$PORT" 2>/dev/null | head -1 | tr -d '\r'; }
r=$(raw 'GET / HTTP/1.1\nHost: h\n\n');  case "$r" in *" 200 "*) ok "bare LF line endings";; *) bad "bare LF" "$r";; esac
r=$(raw 'GET / HTTP/1.1\r\n\r\n');        case "$r" in *" 400 "*) ok "HTTP/1.1 without Host -> 400";; *) bad "no Host" "$r";; esac
r=$(raw 'GET /\r\n\r\n');                case "$r" in *" 400 "*) ok "no version -> 400";; *) bad "no version" "$r";; esac
r=$(raw 'GET  / HTTP/1.1\r\n\r\n');      case "$r" in *" 400 "*) ok "double space -> 400";; *) bad "double space" "$r";; esac
r=$(raw 'GET / HTTP/2.0\r\n\r\n');       case "$r" in *" 505 "*) ok "HTTP/2.0 -> 505";; *) bad "HTTP/2.0" "$r";; esac
r=$(raw 'GET / FTP/1.0\r\n\r\n');        case "$r" in *" 400 "*) ok "bad version -> 400";; *) bad "bad version" "$r";; esac
r=$(raw 'garbage\r\n\r\n');              case "$r" in *" 400 "*) ok "garbage -> 400";; *) bad "garbage" "$r";; esac
r=$(raw 'GET http://x/ HTTP/1.1\r\nHost: x\r\n\r\n'); case "$r" in *" 200 "*) ok "absolute-form -> 200";; *) bad "absolute-form" "$r";; esac
r=$(raw 'BREW / HTTP/1.1\r\nHost: x\r\n\r\n'); case "$r" in *" 501 "*) ok "unknown method -> 501";; *) bad "unknown method" "$r";; esac
big=$(awk 'BEGIN{for(i=0;i<9000;i++)printf "a"}')
r=$(raw "GET / HTTP/1.1\r\nX: $big\r\n\r\n"); case "$r" in *" 431 "*) ok "9KB headers -> 431";; *) bad "431" "$r";; esac
r=$(raw "GET /$big HTTP/1.1\r\nHost: h\r\n\r\n"); case "$r" in *" 414 "*) ok "9KB request-target -> 414";; *) bad "414" "$r";; esac
r=$(printf 'GET / HTTP/1.1\r\nX: a\0b\r\n\r\n' | nc -w 3 127.0.0.1 "$PORT" 2>/dev/null | head -1 | tr -d '\r'); case "$r" in *" 400 "*) ok "NUL in head -> 400";; *) bad "NUL" "$r";; esac

# slowloris: partial request, child must die after timeout (4s)
( printf 'GET / HTTP/1.1\r\nX: '; sleep 7 ) | nc 127.0.0.1 "$PORT" >/dev/null 2>&1 &
sleep 1
kids=$(pgrep -P $SPID | wc -l | tr -d ' ')
[ "$kids" -ge 1 ] && ok "slowloris child spawned ($kids)" || bad "slowloris child" "$kids"
# Linux builds with the seccomp filter say so in -h; the child is filtered
# before it reads the request, so the waiting child must show mode 2.
kid=$(pgrep -P $SPID | head -1)
if [ -n "$kid" ] && [ -r /proc/$kid/status ] && "$BIN" -h 2>&1 | grep -q seccomp; then
  sc=$(awk '/^Seccomp:/ {print $2}' /proc/$kid/status)
  [ "$sc" = 2 ] && ok "child under seccomp filter" || bad "child seccomp mode" "$sc"
fi
sleep 5
kids=$(pgrep -P $SPID | wc -l | tr -d ' ')
[ "$kids" = 0 ] && ok "slowloris child reaped after timeout" || bad "slowloris reap" "$kids"

# privilege check: parent runs as nobody with cwd /
u=$(ps -o user= -p $SPID | tr -d ' '); [ "$u" = "nobody" ] && ok "parent runs as nobody" || bad "parent user" "$u"
if [ -r /proc/$SPID/root ]; then
  rt=$(readlink /proc/$SPID/root); [ "$rt" = "$(cd "$ROOT" && pwd -P)" ] && ok "chroot is docroot" || bad "chroot" "$rt"
  cw=$(readlink /proc/$SPID/cwd); [ "$cw" = "$(cd "$ROOT" && pwd -P)" ] && ok "cwd is chroot /" || bad "cwd" "$cw"
  caps=$(grep CapEff /proc/$SPID/status | awk '{print $2}'); [ "$caps" = "0000000000000000" ] && ok "no capabilities" || bad "CapEff" "$caps"
  nnp=$(grep NoNewPrivs /proc/$SPID/status | awk '{print $2}'); [ "$nnp" = 1 ] && ok "NoNewPrivs set" || bad "NoNewPrivs" "$nnp"
fi

# connection limit: 3 slow clients + 1 more -> 503
for i in 1 2 3; do ( sleep 3 ) | nc 127.0.0.1 "$PORT" >/dev/null 2>&1 & done
sleep 0.5
expect 503 "4th connection over -c 3" "$U/"
sleep 3.5

# clean shutdown
kill -TERM $SPID; sleep 0.5
kill -0 $SPID 2>/dev/null && bad "SIGTERM shutdown" "still running" || ok "SIGTERM shutdown"
san=$(grep -cE 'Sanitizer|runtime error' "$ROOT.log"); [ "$san" = 0 ] && ok "no sanitizer reports in log" || bad "sanitizer reports" "$san"
echo "--- server log tail:"; tail -5 "$ROOT.log"

# ---------------------------------------------------------------- HTTPS
if "$BIN" -h 2>&1 | grep -q 'serve HTTPS' && have openssl; then
  TPORT=$((PORT+1)); T=https://127.0.0.1:$TPORT
  mkdir "$ROOT.tls"
  openssl req -x509 -newkey rsa:2048 -nodes -keyout "$ROOT.tls/key.pem" \
      -out "$ROOT.tls/cert.pem" -subj /CN=localhost -days 2 >/dev/null 2>&1 || { echo "openssl req failed"; exit 2; }
  echo "--- https on port $TPORT"
  cp "$ROOT.tls/key.pem" "$ROOT/leaked.pem"
  "$BIN" -p "$TPORT" -C "$ROOT.tls/cert.pem" -K "$ROOT/leaked.pem" "$ROOT" >/dev/null 2>&1 \
      && bad "key inside docroot refused" "started" || ok "key inside docroot refused"
  rm -f "$ROOT/leaked.pem"
  "$BIN" -p "$TPORT" -t 4 -c 3 -C "$ROOT.tls/cert.pem" -K "$ROOT.tls/key.pem" "$ROOT" 2>"$ROOT.tlslog" &
  TPID=$!
  i=0; until code -k "$T/" >/dev/null 2>&1 || [ $i -ge 50 ]; do i=$((i+1)); sleep 0.1; done
  expect 200 "https GET /"            -k "$T/"
  expect 200 "https HEAD /"           -k -I "$T/"
  expect 404 "https GET /missing"     -k "$T/missing"
  expect 301 "https GET /sub"         -k "$T/sub"
  expect 400 "https GET /../etc/passwd" -k --path-as-is "$T/../etc/passwd"
  expect 405 "https POST /"           -k -X POST "$T/"
  curl -sk -o "$ROOT.dl" "$T/big.bin"
  [ "$(sha "$ROOT/big.bin")" = "$(sha "$ROOT.dl")" ] && ok "https big.bin sha256 matches" || bad "https big.bin sha256" "mismatch"
  rm -f "$ROOT.dl"
  r=$(printf 'GET / HTTP/1.1\r\nHost: h\r\n\r\n' | nc -w 3 127.0.0.1 "$TPORT" 2>/dev/null | head -1 | tr -d '\r')
  case "$r" in *" 400 "*) ok "plain HTTP on https port -> 400";; *) bad "plain HTTP on https port" "$r";; esac
  proto=$(echo | openssl s_client -connect 127.0.0.1:"$TPORT" 2>/dev/null | grep -E '^ *Protocol *:' | head -1 | sed 's/.*: *//')
  case "$proto" in TLSv1.2|TLSv1.3) ok "negotiated $proto";; *) bad "negotiated protocol" "$proto";; esac
  if openssl s_client -help 2>&1 | grep -q -- '-tls1_1'; then
    echo | openssl s_client -connect 127.0.0.1:"$TPORT" -tls1_1 >/dev/null 2>&1 \
        && bad "TLS 1.1 refused" "accepted" || ok "TLS 1.1 refused"
  fi
  ( sleep 7 ) | nc 127.0.0.1 "$TPORT" >/dev/null 2>&1 &
  sleep 1
  kids=$(pgrep -P $TPID | wc -l | tr -d ' ')
  [ "$kids" -ge 1 ] && ok "https idle client child spawned ($kids)" || bad "https idle child" "$kids"
  sleep 5
  kids=$(pgrep -P $TPID | wc -l | tr -d ' ')
  [ "$kids" = 0 ] && ok "https idle child reaped after timeout" || bad "https idle reap" "$kids"
  kill -TERM $TPID; sleep 0.5
  kill -0 $TPID 2>/dev/null && bad "https SIGTERM shutdown" "still running" || ok "https SIGTERM shutdown"
  san=$(grep -cE 'Sanitizer|runtime error' "$ROOT.tlslog"); [ "$san" = 0 ] && ok "no sanitizer reports in https log" || bad "https sanitizer reports" "$san"
  echo "--- https log tail:"; tail -4 "$ROOT.tlslog"
else
  echo "--- https: skipped ($BIN has no TLS support or openssl missing)"
fi
echo "=== pass=$pass fail=$fail"
[ $fail = 0 ]
