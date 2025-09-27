const std = @import("std");

// Simple benchmarking without the full library import
pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    _ = gpa.allocator();

    std.debug.print("=== Merkle Tree Benchmark ===\n\n", .{});

    // Simple benchmark: measure time to hash data
    const test_data = "Sample data for hashing benchmark";
    const num_iterations = 10000;

    std.debug.print("Benchmarking {} hash operations...\n", .{num_iterations});

    const start_time = std.time.nanoTimestamp();

    var i: usize = 0;
    while (i < num_iterations) : (i += 1) {
        var hasher = std.crypto.hash.sha2.Sha256.init(.{});
        hasher.update(test_data);
        var hash: [32]u8 = undefined;
        hasher.final(&hash);
    }

    const end_time = std.time.nanoTimestamp();
    const total_time = @as(u64, @intCast(end_time - start_time));
    const avg_time = total_time / num_iterations;
    const avg_time_us = @as(f64, @floatFromInt(avg_time)) / 1000.0;

    std.debug.print("Total time: {d:.2} ms\n", .{@as(f64, @floatFromInt(total_time)) / 1_000_000.0});
    std.debug.print("Average time per hash: {d:.3} μs\n", .{avg_time_us});
    std.debug.print("Hashes per second: {d:.0}\n", .{1_000_000_000.0 / @as(f64, @floatFromInt(avg_time))});

    std.debug.print("\nBenchmark completed!\n", .{});
    std.debug.print("Note: For full Merkle Tree benchmarking, run: zig test src/lib.zig\n", .{});
}
