const std = @import("std");
const merkle = @import("merkle-tree");
const print = std.debug.print;

fn benchmarkMerkleTree(allocator: std.mem.Allocator, num_items: usize) !u64 {
    var tree = merkle.MerkleTree.init(allocator);
    defer tree.deinit();

    // Generate test data
    var data_items = std.ArrayList([]u8){};
    defer {
        for (data_items.items) |item| {
            allocator.free(item);
        }
        data_items.deinit(allocator);
    }

    for (0..num_items) |i| {
        const data = try std.fmt.allocPrint(allocator, "Data item {}", .{i});
        try data_items.append(allocator, data);
    }

    // Benchmark the tree building
    const start_time = std.time.nanoTimestamp();

    for (data_items.items) |item| {
        try tree.addData(item);
    }

    _ = try tree.getRoot();

    const end_time = std.time.nanoTimestamp();
    return @intCast(end_time - start_time);
}

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    print("=== Merkle Tree Benchmark ===\n\n");

    const test_sizes = [_]usize{ 10, 100, 1000, 10000 };

    for (test_sizes) |size| {
        print("Benchmarking {} items...\n", .{size});

        const num_runs = 5;
        var total_time: u64 = 0;

        for (0..num_runs) |_| {
            const time = try benchmarkMerkleTree(allocator, size);
            total_time += time;
        }

        const avg_time = total_time / num_runs;
        const avg_time_ms = @as(f64, @floatFromInt(avg_time)) / 1_000_000.0;

        print("  Average time: {d:.2} ms\n", .{avg_time_ms});
        print("  Time per item: {d:.2} μs\n", .{avg_time_ms * 1000.0 / @as(f64, @floatFromInt(size))});
        print("\n");
    }

    print("Benchmark completed!\n");
}
