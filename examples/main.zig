const std = @import("std");
const merkle = @import("merkle-tree-zig");

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    std.debug.print("=== Merkle Tree Example ===\n\n", .{});

    // Create a new Merkle Tree Builder
    var builder = merkle.MerkleTreeBuilder.init(allocator);
    defer builder.deinit();

    // Add some sample data (needs to be hashed first)
    const sample_data = [_][]const u8{
        "Transaction 1: Alice sends 10 BTC to Bob",
        "Transaction 2: Bob sends 5 BTC to Charlie",
        "Transaction 3: Charlie sends 3 BTC to Dave",
        "Transaction 4: Dave sends 1 BTC to Eve",
    };

    std.debug.print("Adding hashed data to Merkle Tree:\n", .{});
    for (sample_data, 0..) |data, i| {
        const hash = try merkle.hashData(allocator, data);
        defer allocator.free(hash);
        try builder.addData(hash);
        std.debug.print("  {}. {s}\n", .{ i + 1, data });
    }

    // Build the tree
    var tree = try builder.build();
    defer tree.deinit();

    const root_hash = tree.getRoot();
    const root_hex = try merkle.hashToHex(allocator, root_hash);
    defer allocator.free(root_hex);

    std.debug.print("\nMerkle Root (hex): {s}\n", .{root_hex});
    std.debug.print("Root hash length: {} bytes\n", .{root_hash.len});

    // Demonstrate with different data
    std.debug.print("\n=== Comparing with different data ===\n", .{});

    var builder2 = merkle.MerkleTreeBuilder.init(allocator);
    defer builder2.deinit();

    const different_data = [_][]const u8{
        "Transaction 1: Alice sends 10 BTC to Bob",
        "Transaction 2: Bob sends 5 BTC to Charlie",
        "Transaction 3: Charlie sends 3 BTC to Dave",
        "Transaction 4: Dave sends 2 BTC to Eve", // Changed amount
    };

    for (different_data) |data| {
        const hash = try merkle.hashData(allocator, data);
        defer allocator.free(hash);
        try builder2.addData(hash);
    }

    var tree2 = try builder2.build();
    defer tree2.deinit();

    const root_hash2 = tree2.getRoot();
    const root_hex2 = try merkle.hashToHex(allocator, root_hash2);
    defer allocator.free(root_hex2);

    std.debug.print("Original root:  {s}\n", .{root_hex});
    std.debug.print("Modified root:  {s}\n", .{root_hex2});
    std.debug.print("Roots are equal: {}\n", .{std.mem.eql(u8, root_hash, root_hash2)});

    // Demonstrate utility function
    std.debug.print("\n=== Using utility function ===\n", .{});
    const simple_data = [_][]const u8{ "A", "B", "C", "D" };

    // Hash the simple data first
    var hashed_simple_data: [4][]const u8 = undefined;
    for (simple_data, 0..) |data, i| {
        hashed_simple_data[i] = try merkle.hashData(allocator, data);
    }
    defer {
        for (hashed_simple_data) |hash| {
            allocator.free(hash);
        }
    }

    var simple_tree = try merkle.createMerkleTree(allocator, &hashed_simple_data);
    defer simple_tree.deinit();

    const simple_root = simple_tree.getRoot();
    const simple_hex = try merkle.hashToHex(allocator, simple_root);
    defer allocator.free(simple_hex);

    std.debug.print("Simple tree root: {s}\n", .{simple_hex});

    std.debug.print("\nExample completed successfully!\n", .{});
}
