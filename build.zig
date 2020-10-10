const Pkg = @import("std").build.Pkg;
const Builder = @import("std").build.Builder;
const CrossTarget = @import("std").zig.CrossTarget;
const Abi = @import("std").Target.Abi;

pub fn build(b: *Builder) void {
    // Standard target options allows the person running `zig build` to choose
    // what target to build for. Here we do not override the defaults, which
    // means any target is allowed, and the default is native. Other options
    // for restricting supported target set are available.
    const target = b.standardTargetOptions(.{ .default_target = CrossTarget{ .abi = Abi.gnu } });

    // Standard release options allow the person running `zig build` to select
    // between Debug, ReleaseSafe, ReleaseFast, and ReleaseSmall.
    const mode = b.standardReleaseOptions();

    const exe = b.addExecutable("http-server", "src/main.zig");
    exe.addPackage(zig_network);
    exe.setTarget(target);
    exe.setBuildMode(mode);
    exe.install();

    const tests = b.addTest("src/blocklist.zig");
    tests.addPackage(zig_network);
    tests.setTarget(target);
    tests.setBuildMode(mode);

    const run_cmd = exe.run();
    run_cmd.step.dependOn(b.getInstallStep());

    const run_step = b.step("run", "Run the app");
    run_step.dependOn(&run_cmd.step);

    const test_step = b.step("test", "Run tests");
    test_step.dependOn(&tests.step);
}

const zig_network = Pkg{ .name = "network", .path = "dependencies/zig-network/network.zig" };
