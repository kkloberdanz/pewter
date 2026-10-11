// pewter - fully static build with Zig and musl libc.
//
//   zig build                       static pewter for <host cpu>-linux-musl
//   zig build -Dtls                 the same, with HTTPS (static LibreSSL)
//   zig build -Dtarget=x86_64-linux-musl
//   zig build -Dtarget=aarch64-linux-musl -Dtls
//
// The result is zig-out/bin/pewter: a static-PIE ELF with no dynamic
// loader and no shared libraries, so it runs on any Linux kernel of the
// same architecture and is a sensible thing to drop into an empty
// container.  The Makefile remains the build for dynamically linked
// binaries against the system libc and OpenSSL.
//
// The compiler flags mirror the Makefile: strict C89 with the full
// warning set as errors, -O2 (-Doptimize=safe), stack protector, trapping
// signed overflow and trapping undefined behaviour.
//
// HTTPS needs a LibreSSL built for musl.  -Dtls pulls LibreSSL in as a
// Zig package (allyourcodebase/libressl, pinned by hash in
// build.zig.zon) and compiles it from source into the binary.  The
// package is lazy: a plain `zig build` never downloads it.  The first
// `zig build -Dtls` needs network access; `zig build --fetch -Dtls`
// fetches it ahead of time for an offline build.

const std = @import("std");

pub fn build(b: *std.Build) void {
    // Default to the host CPU on Linux with musl, so `zig build` on macOS or
    // glibc Linux still yields the static Linux binary this file is for.
    const target = b.standardTargetOptions(.{
        .default_target = .{ .os_tag = .linux, .abi = .musl },
    });
    // Default to the optimised, hardened build (zig's "safe" mode: -O2 with
    // undefined behaviour trapped).  -Doptimize=debug gives an unoptimised
    // build with debug info; --release=fast/small are honoured too.
    const optimize: std.builtin.Optimize = b.option(std.builtin.Optimize, "optimize", "Prioritize performance, safety, or binary size (default: safe)") orelse
        switch (b.graph.release_mode) {
            .off, .any, .safe => .safe,
            .fast => .fast,
            .small => .small,
        };

    const tls = b.option(bool, "tls", "Build with HTTPS support (static LibreSSL, default: false)") orelse false;
    const strip = b.option(bool, "strip", "Strip debug info (default: true unless -Doptimize=debug)") orelse
        (optimize != .debug);
    const sendfile = b.option(bool, "sendfile", "Use sendfile(2) for plain HTTP (default: true)") orelse true;

    const mod = b.createModule(.{
        .target = target,
        .optimize = optimize,
        .link_libc = true,
        .strip = strip,
        // Position independent code so the executable can be a static-PIE
        // and get address-space randomisation without a dynamic loader.
        .pic = true,
        .stack_protector = true,
        // Trap on undefined behaviour in C (clang -fsanitize=undefined
        // -fsanitize-trap=undefined); no runtime library is linked.
        .sanitize_c = .trap,
    });

    mod.addCSourceFile(.{
        .file = b.path("pewter.c"),
        .flags = &cflags,
    });

    if (!sendfile) mod.addCMacro("PEWTER_NO_SENDFILE", "1");

    if (tls) {
        // Lazy: only fetched (and only compiled) for -Dtls.  When it has
        // not been fetched yet, zig fetches it after this function returns
        // and runs the build script again.
        const dep = b.lazyDependency("libressl", .{
            .target = target,
            .optimize = optimize,
        }) orelse return;
        const ssl = dep.artifact("ssl");
        const crypto = dep.artifact("crypto");
        // The package builds non-PIC archives; a static-PIE needs PIC.
        ssl.root_module.pic = true;
        crypto.root_module.pic = true;

        // System include path so the LibreSSL headers are exempt from
        // -pedantic-errors (they use C99 trailing enum commas), and the
        // archives as plain link inputs so no duplicate -I is added.
        mod.addSystemIncludePath(ssl.getEmittedIncludeTree());
        mod.addObjectFile(ssl.getEmittedBin());
        mod.addObjectFile(crypto.getEmittedBin());
        mod.addCMacro("PEWTER_TLS", "1");
    }

    const exe = b.addExecutable(.{
        .name = "pewter",
        .root_module = mod,
        .linkage = .static,
    });
    exe.pie = true;
    b.installArtifact(exe);
}

// Same flags as the Makefile, minus the ones Zig sets itself from the
// module options above (-O2, -fPIE, -fstack-protector-strong,
// -D_FORTIFY_SOURCE=2, -fsanitize=undefined -fsanitize-trap=undefined).
const cflags = [_][]const u8{
    "-std=c89",
    "-pedantic",
    "-pedantic-errors",
    "-Wall",
    "-Wextra",
    "-Wshadow",
    "-Wconversion",
    "-Wsign-conversion",
    "-Wstrict-prototypes",
    "-Wmissing-prototypes",
    "-Wmissing-declarations",
    "-Wcast-qual",
    "-Wcast-align",
    "-Wpointer-arith",
    "-Wwrite-strings",
    "-Wformat=2",
    "-Wundef",
    "-Wredundant-decls",
    "-Wnested-externs",
    "-Wswitch-default",
    "-Wunreachable-code",
    "-Wvla",
    "-Wdouble-promotion",
    "-Wfloat-equal",
    "-Wbad-function-cast",
    "-Werror",
    "-ftrapv",
    "-fno-strict-aliasing",
    "-fno-delete-null-pointer-checks",
};
