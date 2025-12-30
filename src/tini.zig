const Allocator = @import("std").mem.Allocator;
const config = @import("config");
const expect = @import("std").testing.expect;
const log = @import("std").log;
const posix = @import("std").posix;
const std = @import("std");
const SIG = @import("std").c.SIG;
const W = @import("std").c.W;

const getopt = @import("getopt.zig");

const DEFAULT_VERBOSITY = 1;

const HAS_SUBREAPER = config.PR_SET_CHILD_SUBREAPER != null;
const OPT_STRING = if (config.PR_SET_CHILD_SUBREAPER != null) "p:hvwgle:s" else "p:hvwgle:";
const SUBREAPER_ENV_VAR = if (config.PR_SET_CHILD_SUBREAPER != null) "TINI_SUBREAPER" else null;

const VERBOSITY_ENV_VAR = "TINI_VERBOSITY";
const KILL_PROCESS_GROUP_GROUP_ENV_VAR = "TINI_KILL_PROCESS_GROUP";

const TINI_VERSION_STRING = "tini version " ++ config.TINI_VERSION ++ config.TINI_GIT;

const STATUS_MAX = 255;
const STATUS_MIN = 0;

const signal_configuration_t = struct {
    sigmask_ptr: *const std.c.sigset_t,
    sigttin_action_ptr: *const std.c.Sigaction,
    sigttou_action_ptr: *const std.c.Sigaction,
};

const signal_name_t = struct {
    name: []const u8,
    number: c_uint,
};

const signal_names: []const signal_name_t = &.{
    .{ .name = "SIGHUP", .number = SIG.HUP },
    .{ .name = "SIGINT", .number = SIG.INT },
    .{ .name = "SIGQUIT", .number = SIG.QUIT },
    .{ .name = "SIGILL", .number = SIG.ILL },
    .{ .name = "SIGTRAP", .number = SIG.TRAP },
    .{ .name = "SIGABRT", .number = SIG.ABRT },
    .{ .name = "SIGFPE", .number = SIG.FPE },
    .{ .name = "SIGKILL", .number = SIG.KILL },
    .{ .name = "SIGUSR1", .number = SIG.USR1 },
    .{ .name = "SIGSEGV", .number = SIG.SEGV },
    .{ .name = "SIGUSR2", .number = SIG.USR2 },
    .{ .name = "SIGPIPE", .number = SIG.PIPE },
    .{ .name = "SIGALRM", .number = SIG.ALRM },
    .{ .name = "SIGTERM", .number = SIG.TERM },
    .{ .name = "SIGCHLD", .number = SIG.CHLD },
    .{ .name = "SIGCONT", .number = SIG.CONT },
    .{ .name = "SIGSTOP", .number = SIG.STOP },
    .{ .name = "SIGTSTP", .number = SIG.TSTP },
    .{ .name = "SIGTTIN", .number = SIG.TTIN },
    .{ .name = "SIGTTOU", .number = SIG.TTOU },
    .{ .name = "SIGURG", .number = SIG.URG },
    .{ .name = "SIGXCPU", .number = SIG.XCPU },
    .{ .name = "SIGXFSZ", .number = SIG.XFSZ },
    .{ .name = "SIGVTALRM", .number = SIG.VTALRM },
    .{ .name = "SIGPROF", .number = SIG.PROF },
    .{ .name = "SIGWINCH", .number = SIG.WINCH },
    .{ .name = "SIGSYS", .number = SIG.SYS },
};

var verbosity: u8 = DEFAULT_VERBOSITY;

var expect_status = std.bit_set.StaticBitSet(STATUS_MAX - STATUS_MIN + 1).initEmpty();

var subreaper: c_uint = 0;
var parent_death_signal: c_uint = 0;
var kill_process_group: c_uint = 0;

var warn_on_reap: c_uint = 0;

const ts: std.c.timespec = .{ .sec = 1, .nsec = 0 };

const reaper_warning = "Tini is not running as PID 1 " ++
    (if (HAS_SUBREAPER) "and isn't registered as a child subreaper" else "") ++
    ".\n" ++
    "Zombie processes will not be re-parented to Tini, so zombie reaping won't work.\n" ++
    "To fix the problem, " ++
    (if (HAS_SUBREAPER) "use the -s option or set the environment variable " ++ SUBREAPER_ENV_VAR ++ " to register Tini as a child subreaper, or " else "") ++
    "run Tini as PID 1.";

const Error = error{
    ConfigureSignals,
    IsolateChild,
    ParseArgs,
    ReapZombies,
    RegisterSubreaper,
    RestoreSignals,
    Spawn,
    WaitAndForwardSignal,
};

// These constants are not defined in Zig's standard library
const PR_SET_PDEATHSIG: c_int = 1;

// These functions are not defined in Zig's standard library
extern "c" fn getpgrp() std.c.pid_t;
extern "c" fn sigtimedwait(set: *const std.c.sigset_t, info: *std.c.siginfo_t, timeout: *const std.c.timespec) c_int;

// Not defined for all platforms in stdlib yet
extern "c" fn tcsetpgrp(fd: std.c.fd_t, pgrp: std.c.pid_t) c_int;

pub const std_options: std.Options = .{
    .logFn = custom_log,
    .log_level = log.Level.debug, // include all logs - it adds only a couple of kilo-bytes
};

fn custom_log(
    comptime message_level: std.log.Level,
    comptime scope: @TypeOf(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    if (@intFromEnum(message_level) <= verbosity) {
        std.log.defaultLog(message_level, scope, format, args);
    }
}

fn restore_signals(sigconf_ptr: *const signal_configuration_t) !void {
    var err = std.c.sigprocmask(SIG.SETMASK, sigconf_ptr.sigmask_ptr, null);
    if (err != 0) {
        log.err("Restoring child signal mask failed: '{t}'", .{posix.errno(err)});
        return Error.RestoreSignals;
    }
    err = std.c.sigaction(SIG.TTIN, sigconf_ptr.sigttin_action_ptr, null);
    if (err != 0) {
        log.err("Restoring SIGTTIN handler failed: '{t}'", .{posix.errno(err)});
        return Error.RestoreSignals;
    }
    err = std.c.sigaction(SIG.TTOU, sigconf_ptr.sigttou_action_ptr, null);
    if (err != 0) {
        log.err("Restoring SIGTTOU handler failed: '{t}'", .{posix.errno(err)});
        return Error.RestoreSignals;
    }
}

fn isolate_child() !void {
    // Put the child into a new process group.
    const err = std.c.setpgid(0, 0);
    if (err < 0) {
        log.err("setpgid failed: {t}", .{posix.errno(err)});
        return Error.IsolateChild;
    }

    // If there is a tty, allocate it to this new process group. We
    // can do this in the child process because we're blocking
    // SIGTTIN / SIGTTOU.

    // Doing it in the child process avoids a race condition scenario
    // if Tini is calling Tini (in which case the grandparent may make the
    // parent the foreground process group, and the actual child ends up...
    // in the background!)
    const errno = posix.errno(tcsetpgrp(std.c.STDIN_FILENO, getpgrp()));
    if (errno != .SUCCESS) {
        if (errno == .NOTTY) {
            log.debug("tcsetpgrp failed: no tty (ok to proceed)", .{});
        } else if (errno == .NXIO) {
            // can occur on lx-branded zones
            log.debug("tcsetpgrp failed: no such device (ok to proceed)", .{});
        } else {
            log.err("tcsetpgrp failed: {t}", .{errno});
            return Error.IsolateChild;
        }
    }
}

fn spawn(sigconf_ptr: *const signal_configuration_t, argv: [:null]const ?[*:0]const u8, child_pid_ptr: *std.c.pid_t) !u8 {
    // TODO: check if tini was a foreground process to begin with (it's not OK to "steal" the foreground!")
    const pid = std.c.fork();
    if (pid < 0) {
        log.err("fork failed: {t}", .{posix.errno(pid)});
        return Error.Spawn;
    } else if (pid == 0) {
        // Put the child in a process group and make it the foreground process if there is a tty.
        try isolate_child();

        // Restore all signal handlers to the way they were before we touched them.
        try restore_signals(sigconf_ptr);

        const err = posix.execvpeZ(argv[0].?, argv, std.c.environ);

        // execvp will only return on an error so make sure that we check the errno
        // and exit with the correct return status for the error that we encountered
        // See: http://www.tldp.org/LDP/abs/html/exitcodes.html#EXITCODESREF
        log.err("exec {s} failed: {t}", .{ argv[0].?, err });
        return switch (err) {
            error.FileNotFound => 127,
            error.AccessDenied => 126,
            else => err,
        };
    } else {
        // Parent
        log.info("Spawned child process '{s}' with pid '{d}'", .{ argv[0].?, pid });
        child_pid_ptr.* = pid;
        return 0;
    }
}

fn print_usage(name: [*:0]const u8, file: *std.fs.File) !void {
    const bname = std.fs.path.basename(std.mem.span(name));
    _ = try file.writeAll(bname);
    _ = try file.writeAll(" (" ++ TINI_VERSION_STRING ++ ")\n");
    _ = try file.writeAll("Usage: ");
    _ = try file.writeAll(bname);
    _ = try file.writeAll(" [OPTIONS] PROGRAM -- [ARGS] | --version\n\n");
    _ = try file.writeAll("Execute a program under the supervision of a valid init process (");
    _ = try file.writeAll(bname);
    _ = try file.writeAll(")\n\n");
    _ = try file.writeAll("Command line options:\n\n");
    _ = try file.writeAll("  --version: Show version and exit.\n");
    _ = try file.writeAll("  -h:       Show this help message and exit.\n");
    if (HAS_SUBREAPER) {
        _ = try file.writeAll("  -s: Register as a process subreaper (requires Linux >= 3.4).\n");
    }
    _ = try file.writeAll("  -p SIGNAL: Trigger SIGNAL when parent dies, e.g. \"-p SIGKILL\".\n");
    _ = try file.writeAll("  -v: Generate more verbose output. Repeat up to 3 times.\n");
    _ = try file.writeAll("  -w: Print a warning when processes are getting reaped.\n");
    _ = try file.writeAll("  -g: Send signals to the child's process group.\n");
    _ = try file.writeAll("  -e EXIT_CODE: Remap EXIT_CODE (from 0 to 255) to 0 (can be repeated).\n");
    _ = try file.writeAll("  -l: Show license and exit.\n");

    _ = try file.writeAll("\n");
    _ = try file.writeAll("Environment variables:\n\n");
    if (HAS_SUBREAPER) {
        _ = try file.writeAll("  " ++ SUBREAPER_ENV_VAR ++ ": Register as a process subreaper (requires Linux >= 3.4).\n");
    }
    _ = try file.writeAll("  " ++ VERBOSITY_ENV_VAR ++ ": Set the verbosity level (default: " ++ std.fmt.comptimePrint("{d}", .{DEFAULT_VERBOSITY}) ++ ").\n");
    _ = try file.writeAll("  " ++ KILL_PROCESS_GROUP_GROUP_ENV_VAR ++ ": Send signals to the child's process group.\n");
    _ = try file.writeAll("\n");
}

fn print_license(file: *std.fs.File) !void {
    _ = try file.writeAll(config.LICENSE);
}

fn set_pdeathsig(arg: []const u8) c_int {
    for (signal_names) |signal| {
        if (std.mem.eql(u8, signal.name, arg)) {
            // Signals start at value "1"
            parent_death_signal = signal.number;
            return 0;
        }
    }
    return 1;
}

fn add_expect_status(arg: []const u8) c_int {
    const status = std.fmt.parseInt(u8, arg, 10) catch return 1;
    if (status < STATUS_MIN or status > STATUS_MAX) {
        return 1;
    }
    expect_status.set(status);
    return 0;
}

fn parse_args(allocator: Allocator, argv: [][*:0]u8, parse_fail_exitcode_ptr: *u8) ![:null]const ?[*:0]const u8 {
    const name = argv[0];
    var stdout = std.fs.File.stdout();

    // We handle --version if it's the *only* argument provided.
    if (argv.len == 2 and std.mem.eql(u8, std.mem.span(argv[1]), "--version")) {
        parse_fail_exitcode_ptr.* = 0;
        try stdout.writeAll(TINI_VERSION_STRING ++ "\n");
        return Error.ParseArgs;
    }

    var opts = getopt.getopt(OPT_STRING);
    while (opts.next()) |maybe_opt| {
        if (maybe_opt) |opt| {
            switch (opt.opt) {
                'h' => {
                    try print_usage(name, &stdout);
                    parse_fail_exitcode_ptr.* = 0;
                    return Error.ParseArgs;
                },
                's' => {
                    if (!HAS_SUBREAPER) {
                        // Should never happen
                        return Error.ParseArgs;
                    }
                    subreaper += 1;
                },
                'p' => {
                    if (set_pdeathsig(opt.arg.?) != 0) {
                        log.err("Not a valid option for -p: {s}", .{opt.arg.?});
                        parse_fail_exitcode_ptr.* = 1;
                        return Error.ParseArgs;
                    }
                },
                'v' => verbosity += 1,
                'w' => warn_on_reap += 1,
                'g' => kill_process_group += 1,
                'e' => {
                    if (add_expect_status(opt.arg.?) != 0) {
                        log.err("Not a valid exit code for -e: {s}", .{opt.arg.?});
                        parse_fail_exitcode_ptr.* = 1;
                        return Error.ParseArgs;
                    }
                },
                'l' => {
                    try print_license(&stdout);
                    parse_fail_exitcode_ptr.* = 0;
                    return Error.ParseArgs;
                },
                '?' => {
                    try print_usage(name, &stdout);
                    return Error.ParseArgs;
                },
                else => {
                    // Should never happen
                    return Error.ParseArgs;
                },
            }
        } else break;
    } else |err| {
        switch (err) {
            getopt.Error.InvalidOption => {
                log.err("Invalid option: -{c}", .{opts.optopt});
                return Error.ParseArgs;
            },
            getopt.Error.MissingArgument => {
                log.err("Option -{c} requires an argument", .{opts.optopt});
                return Error.ParseArgs;
            },
        }
    }

    var child_args_ptr = allocator.allocSentinel(?[*:0]const u8, argv.len - opts.optind, null) catch |err| {
        log.err("Failed to allocate memory for child args: '{t}'", .{err});
        return Error.ParseArgs;
    };
    errdefer allocator.free(child_args_ptr);

    for (0..(argv.len - opts.optind)) |i| {
        child_args_ptr[i] = argv[opts.optind + i];
    }

    if (child_args_ptr.len == 0) {
        try print_usage(name, &stdout);
        return Error.ParseArgs;
    }

    return child_args_ptr;
}

fn parse_env() void {
    if (HAS_SUBREAPER) {
        if (posix.getenv(SUBREAPER_ENV_VAR) != null) {
            subreaper += 1;
        }
    }

    if (posix.getenv(KILL_PROCESS_GROUP_GROUP_ENV_VAR) != null) {
        kill_process_group += 1;
    }
    const env_verbosity = posix.getenv(VERBOSITY_ENV_VAR);
    if (env_verbosity != null) {
        verbosity = std.fmt.parseInt(u8, env_verbosity.?, 10) catch DEFAULT_VERBOSITY;
    }
}

fn register_subreaper() !void {
    if (subreaper > 0) {
        const errno = posix.errno(std.c.prctl(config.PR_SET_CHILD_SUBREAPER.?, @as(c_int, 1)));
        if (errno != .SUCCESS) {
            if (errno == .INVAL) {
                log.err("PR_SET_CHILD_SUBREAPER is unavailable on this platform. Are you using Linux >= 3.4?", .{});
            } else {
                log.err("Failed to register as child subreaper: {t}", .{errno});
            }
            return Error.RegisterSubreaper;
        } else {
            log.debug("Registered as child subreaper", .{});
        }
    }
}

fn reaper_check() void {
    // Check that we can properly reap zombies
    if (std.c.getpid() == 1) {
        return;
    }

    if (HAS_SUBREAPER) {
        var bit: c_int = 0;
        const err = std.c.prctl(config.PR_GET_CHILD_SUBREAPER.?, &bit);
        if (err != 0) {
            log.debug("Failed to read child subreaper attribute: {t}", .{posix.errno(err)});
        } else if (bit == 1) {
            return;
        }
    }

    log.warn("{s}", .{reaper_warning});
}

fn configure_signals(
    parent_sigset_ptr: *std.c.sigset_t,
    sigconf_ptr: *const signal_configuration_t,
) !void {
    // Block all signals that are meant to be collected by the main loop
    parent_sigset_ptr.* = std.posix.sigfillset();
    // These ones shouldn't be collected by the main loop
    const signals_for_tini = [_]c_int{
        SIG.FPE, SIG.ILL,  SIG.SEGV, SIG.BUS, SIG.ABRT, SIG.TRAP,
        SIG.SYS, SIG.TTIN, SIG.TTOU,
    };
    for (signals_for_tini) |sig| {
        if (std.c.sigdelset(parent_sigset_ptr, sig) != 0) {
            log.err("sigdelset failed: '{d}'", .{sig});
            return Error.ConfigureSignals;
        }
    }

    var err = std.c.sigprocmask(SIG.SETMASK, parent_sigset_ptr, @constCast(sigconf_ptr.sigmask_ptr));
    if (err != 0) {
        log.err("sigprocmask failed: '{t}'", .{posix.errno(err)});
        return Error.ConfigureSignals;
    }

    // Handle SIGTTIN and SIGTTOU separately. Since Tini makes the child process group
    // the foreground process group, there's a chance Tini can end up not controlling the tty.
    // If TOSTOP is set on the tty, this could block Tini on writing debug messages. We don't
    // want that. Ignore those signals.
    var ign_action = std.mem.zeroes(std.c.Sigaction);
    ign_action.handler.handler = SIG.IGN;
    _ = std.c.sigemptyset(&ign_action.mask);

    err = std.c.sigaction(SIG.TTIN, &ign_action, @constCast(sigconf_ptr.sigttin_action_ptr));
    if (err != 0) {
        log.err("Failed to ignore SIGTTIN: '{t}'", .{posix.errno(err)});
        return Error.ConfigureSignals;
    }
    err = std.c.sigaction(SIG.TTOU, &ign_action, @constCast(sigconf_ptr.sigttou_action_ptr));
    if (err != 0) {
        log.err("Failed to ignore SIGTTOU: '{t}'", .{posix.errno(err)});
        return Error.ConfigureSignals;
    }
}

fn wait_and_forward_signal(parent_sigset_ptr: *const std.c.sigset_t, child_pid: std.c.pid_t) !void {
    var sig: std.c.siginfo_t = undefined;

    var errno = posix.errno(sigtimedwait(parent_sigset_ptr, &sig, &ts));
    if (errno != .SUCCESS) {
        switch (errno) {
            .AGAIN => {},
            .INTR => {},
            else => {
                log.err("Unexpected error in sigtimedwait: '{t}'", .{errno});
                return Error.WaitAndForwardSignal;
            },
        }
    } else {
        // There is a signal to handle here
        switch (sig.signo) {
            SIG.CHLD => {
                // Special-cased, as we don't forward SIGCHLD. Instead, we'll
                // fallthrough to reaping processes.
                log.debug("Received SIGCHLD", .{});
            },
            else => {
                const pid = if (kill_process_group > 0) -child_pid else child_pid;
                errno = posix.errno(std.c.kill(pid, sig.signo));
                if (errno == .SRCH) {
                    log.warn("Child was dead when forwarding signal", .{});
                } else {
                    log.err("Unexpected error when forwarding signal: '{t}'", .{errno});
                    return Error.WaitAndForwardSignal;
                }
            },
        }
    }
}

fn reap_zombies(child_pid: std.c.pid_t, child_exitcode_ptr: *?u8) !void {
    var current_pid: std.c.pid_t = undefined;
    var current_status: u32 = undefined;

    while (true) {
        current_pid = std.c.waitpid(-1, @ptrCast(&current_status), W.NOHANG);
        switch (current_pid) {
            -1 => {
                const errno = posix.errno(-1);
                if (errno == .CHILD) {
                    log.debug("No child to wait", .{});
                } else {
                    log.err("Error while waiting for pids: '{t}'", .{errno});
                    return Error.ReapZombies;
                }
            },
            0 => log.debug("No child to reap", .{}),
            else => {
                // A child was reaped. Check whether it's the main one. If it is, then
                // set the exit_code, which will cause us to exit once we've reaped everyone else.
                log.debug("Reaped child with pid: '{d}'", .{current_pid});
                if (current_pid == child_pid) {
                    if (W.IFEXITED(current_status)) {
                        // Our process exited normally.
                        log.info("Main child exited normally (with status '{d}')", .{W.EXITSTATUS(current_status)});
                        child_exitcode_ptr.* = W.EXITSTATUS(current_status);
                    } else if (W.IFSIGNALED(current_status)) {
                        // Our process was terminated. Emulate what sh / bash
                        // would do, which is to return 128 + signal number.
                        log.info("Main child exited with signal (with signal '{d}')", .{W.TERMSIG(current_status)});
                        // Be safe, ensure the status code is indeed between 0 and 255.
                        child_exitcode_ptr.* = @intCast((128 + W.TERMSIG(current_status)) % (STATUS_MAX - STATUS_MIN + 1));
                    } else {
                        log.err("Main child exited for unknown reason", .{});
                        return Error.ReapZombies;
                    }

                    // If this exitcode was remapped, then set it to 0.
                    if (expect_status.isSet(child_exitcode_ptr.*.?)) {
                        child_exitcode_ptr.* = 0;
                    }
                } else if (warn_on_reap > 0) {
                    log.warn("Reaped zombie process with pid={d}", .{current_pid});
                }

                // Check if other childs have been reaped.
                continue;
            },
        }

        // If we make it here, that's because we did not continue in the switch case.
        break;
    }
}

pub fn main() !u8 {
    var child_pid: std.c.pid_t = 0;

    // Those are passed to functions to get an exitcode back.
    var child_exitcode: ?u8 = null; // This isn't a valid exitcode, and lets us tell whether the child has exited.
    var parse_exitcode: u8 = 1; // By default, we exit with 1 if parsing fails.

    // Parse command line arguments
    const child_args_ptr = parse_args(std.heap.c_allocator, std.os.argv, &parse_exitcode) catch |err| {
        if (err == Error.ParseArgs) {
            return parse_exitcode;
        }
        return err;
    };
    defer std.heap.c_allocator.free(child_args_ptr);

    // Parse environment
    parse_env();

    // Configure signals
    var parent_sigset = std.mem.zeroes(std.c.sigset_t);
    const child_sigset = std.mem.zeroes(std.c.sigset_t);
    const sigttin_action = std.mem.zeroes(std.c.Sigaction);
    const sigttou_action = std.mem.zeroes(std.c.Sigaction);
    var child_sigconf: signal_configuration_t = .{
        .sigmask_ptr = &child_sigset,
        .sigttin_action_ptr = &sigttin_action,
        .sigttou_action_ptr = &sigttou_action,
    };

    configure_signals(&parent_sigset, &child_sigconf) catch return 1;

    // Trigger signal on this process when the parent process exits.
    if (parent_death_signal != 0) {
        const err = std.c.prctl(PR_SET_PDEATHSIG, parent_death_signal);
        if (err != 0) {
            log.err("Failed to set up parent death signal: {t}", .{posix.errno(err)});
            return 1;
        }
    }

    if (HAS_SUBREAPER) {
        // If available and requested, register as a subreaper
        register_subreaper() catch return 1;
    }

    // Are we going to reap zombies properly? If not, warn.
    reaper_check();

    // Go on
    const spawn_ret = spawn(&child_sigconf, child_args_ptr, &child_pid) catch return 1;
    if (spawn_ret != 0) {
        return spawn_ret;
    }

    while (true) {
        // Wait for one signal, and forward it
        wait_and_forward_signal(&parent_sigset, child_pid) catch return 1;

        // Now, reap zombies
        reap_zombies(child_pid, &child_exitcode) catch return 1;

        if (child_exitcode != null) {
            log.debug("Exiting: child has exited", .{});
            return child_exitcode.?;
        }
    }
}
