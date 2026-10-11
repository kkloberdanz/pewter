# pewter - minimal static HTTP server
#
# Strictly POSIX make: works with GNU make, bmake and FreeBSD make.
# Platform differences live in pewter.c, not here.
#
# Override any group on the command line, e.g.
#   make WERROR=                      # don't treat warnings as errors
#   make EXTRA=-DPEWTER_NO_SENDFILE   # force the read/write fallback
#   make LDFLAGS="-Wl,-pie,-z,relro,-z,now"   # extra hardening on Linux/FreeBSD
#
# `make tls` builds the same `pewter` binary with HTTPS support.  It needs
# OpenSSL or LibreSSL headers and libraries; the recipe asks pkg-config
# where they are (Debian: libssl-dev; macOS: brew install openssl) and falls
# back to the system include path.  To point at a specific install:
#   make tls TLS_INC=-isystem/opt/homebrew/opt/openssl@3/include \
#            TLS_LIB=-L/opt/homebrew/opt/openssl@3/lib
# Plain and TLS builds share the file name, so the tls targets always
# rebuild; `make clean && make` returns to the plain build.
#
# `make kcc` builds with a minimal compiler that understands only
# -c -S -o -I -D -U -std= (kcc, and others of that shape): every warning,
# optimisation, hardening and linker group is emptied.  Point it elsewhere
# with `make kcc KCC=path/to/cc`, or override the groups by hand for any
# other compiler:
#   make CC=tcc WARN= WERROR= OPT= HARDEN= LDFLAGS=

CC       = cc

STD      = -std=c89 -pedantic -pedantic-errors
WARN     = -Wall -Wextra -Wshadow -Wconversion -Wsign-conversion \
           -Wstrict-prototypes -Wmissing-prototypes -Wmissing-declarations \
           -Wcast-qual -Wcast-align -Wpointer-arith -Wwrite-strings \
           -Wformat=2 -Wundef -Wredundant-decls -Wnested-externs \
           -Wswitch-default -Wunreachable-code -Wvla -Wdouble-promotion \
           -Wfloat-equal -Wbad-function-cast
WERROR   = -Werror
OPT      = -O2
HARDEN   = -fstack-protector-strong -D_FORTIFY_SOURCE=2 -fPIE -ftrapv \
           -fno-strict-aliasing -fno-delete-null-pointer-checks
EXTRA    =
CFLAGS   = $(STD) $(WARN) $(WERROR) $(OPT) $(HARDEN) $(EXTRA)
LDFLAGS  = -Wl,-pie

DEBUG_OPT    = -O0 -g3
DEBUG_HARDEN = -fsanitize=address,undefined -fno-omit-frame-pointer
DEBUG_LD     = -fsanitize=address,undefined

# HTTPS build.  The $$(...) substitutions run in the shell when the tls
# recipe executes; -I becomes -isystem so the library headers are exempt
# from -pedantic-errors.  TLSC/TLSL are empty unless a tls target sets them.
TLS_INC  = $$(pkg-config --cflags-only-I openssl 2>/dev/null | sed 's/-I/-isystem/g')
TLS_LIB  = $$(pkg-config --libs-only-L openssl 2>/dev/null)
TLS_LIBS = -lssl -lcrypto
TLSC     =
TLSL     =

# In-process parser fuzzer (fuzz_parse.c); needs clang with libFuzzer.
FUZZ_CC  = clang
FUZZ_FLAGS = -g -O1 -fsanitize=fuzzer,address,undefined -fno-omit-frame-pointer

# Compiler for the `kcc` target.  Not bare `kcc`: macOS ships an unrelated
# Kerberos tool at /usr/bin/kcc that would shadow it.
KCC      = $(HOME)/bin/kcc

PREFIX   = /usr/local
BINDIR   = $(PREFIX)/bin

all: pewter

pewter: pewter.c
	$(CC) $(CFLAGS) $(TLSC) $(LDFLAGS) -o $@ pewter.c $(TLSL)

# Sanitizer build for running the test matrix; never install this one.
debug:
	$(MAKE) pewter-debug OPT="$(DEBUG_OPT)" HARDEN="$(DEBUG_HARDEN)" LDFLAGS="$(DEBUG_LD)"

pewter-debug: pewter.c
	$(CC) $(CFLAGS) $(TLSC) $(LDFLAGS) -o $@ pewter.c $(TLSL)

# HTTPS builds of the same two binaries.
tls:
	rm -f pewter
	$(MAKE) pewter TLSC="-DPEWTER_TLS $(TLS_INC)" TLSL="$(TLS_LIB) $(TLS_LIBS)"

debug-tls:
	rm -f pewter-debug
	$(MAKE) pewter-debug OPT="$(DEBUG_OPT)" HARDEN="$(DEBUG_HARDEN)" LDFLAGS="$(DEBUG_LD)" \
		TLSC="-DPEWTER_TLS $(TLS_INC)" TLSL="$(TLS_LIB) $(TLS_LIBS)"

# Minimal-compiler build: same source, same binary name, no extra flags.
kcc:
	rm -f pewter
	$(MAKE) pewter CC="$(KCC)" STD=-std=c89 WARN= WERROR= OPT= HARDEN= LDFLAGS=

fuzz: pewter-fuzz

pewter-fuzz: pewter.c fuzz_parse.c
	$(FUZZ_CC) $(FUZZ_FLAGS) -o $@ fuzz_parse.c

install: pewter
	mkdir -p $(DESTDIR)$(BINDIR)
	cp pewter $(DESTDIR)$(BINDIR)/pewter
	chmod 755 $(DESTDIR)$(BINDIR)/pewter

clean:
	rm -f pewter pewter-debug pewter-fuzz

.PHONY: all debug tls debug-tls kcc fuzz install clean
