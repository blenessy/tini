const std = @import("std");

fn readLicense(allocator: std.mem.Allocator) ![]const u8 {
    const file = try std.fs.cwd().openFile("LICENSE", .{});
    defer file.close();

    const stat = try file.stat();
    const buf: []u8 = try allocator.alloc(u8, stat.size);
    _ = try file.readAll(buf);

    return buf;
}

pub fn build(b: *std.Build) !void {
    const target_query = std.Target.Query{
        .cpu_arch = .x86_64, // Set the architecture you are targeting
        .os_tag = .linux, // Set the OS tag
        // Use .baseline for a generic, universally compatible CPU feature set
        .cpu_model = .baseline,
    };
    const target = b.resolveTargetQuery(target_query);
    const optimize = b.standardOptimizeOption(.{});

    const exe = b.addExecutable(.{
        .name = "tini",
        .linkage = .static,
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tini.zig"),
            .target = target,
            .optimize = optimize,
            .strip = true,
            .single_threaded = true,
        }),
    });
    exe.linkLibC();

    const zon = @import("build.zig.zon");

    // custom build options
    const tini_git = b.option([]const u8, "TINI_GIT", "GIT suffix to append to version string") orelse "";
    const pr_set_child_subreaper = b.option(c_int, "PR_SET_CHILD_SUBREAPER", "Set to 36 for old (<3.4) linux kernel support") orelse null;
    const pr_get_child_subreaper = b.option(c_int, "PR_GET_CHILD_SUBREAPER", "Set to 37 for old (<3.4) linux kernel support") orelse null;

    // bind options to the config module
    const options = b.addOptions();
    options.addOption([]const u8, "TINI_VERSION", zon.version);
    options.addOption([]const u8, "TINI_GIT", tini_git);
    options.addOption(?c_int, "PR_SET_CHILD_SUBREAPER", pr_set_child_subreaper);
    options.addOption(?c_int, "PR_GET_CHILD_SUBREAPER", pr_get_child_subreaper);
    const license = try readLicense(b.allocator);
    defer b.allocator.free(license);
    options.addOption([]const u8, "LICENSE", license);
    exe.root_module.addOptions("config", options);

    b.installArtifact(exe);

    // configure the "run" step
    const run_step = b.step("run", "Run the app");
    const run_cmd = b.addRunArtifact(exe);
    run_step.dependOn(&run_cmd.step);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| {
        run_cmd.addArgs(args);
    }

    // configure the "test" step
    const test_step = b.step("test", "Run unit tests");
    const exe_tests = b.addTest(.{
        .root_module = b.createModule(.{
            .root_source_file = b.path("src/tini.zig"),
            .target = target,
        }),
    });
    const run_exe_tests = b.addRunArtifact(exe_tests);
    test_step.dependOn(&run_exe_tests.step);
}
