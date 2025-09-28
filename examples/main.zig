const std = @import("std");
const merkle = @import("merkle-tree-zig");

// pub fn main() !void {
//     var gpa = std.heap.GeneralPurposeAllocator(.{}){};
//     defer _ = gpa.deinit();
//     const allocator = gpa.allocator();

//     std.debug.print("=== Merkle Tree Example ===\n\n", .{});

//     // Create a new Merkle Tree Builder
//     var builder = merkle.MerkleTreeBuilder.init(allocator);
//     defer builder.deinit();

//     // Add some sample data (needs to be hashed first)
//     const sample_data = [_][]const u8{
//         "Transaction 1: Alice sends 10 BTC to Bob",
//         "Transaction 2: Bob sends 5 BTC to Charlie",
//         "Transaction 3: Charlie sends 3 BTC to Dave",
//         "Transaction 4: Dave sends 1 BTC to Eve",
//     };

//     std.debug.print("Adding hashed data to Merkle Tree:\n", .{});
//     for (sample_data, 0..) |data, i| {
//         const hash = try merkle.hashData(allocator, data);
//         defer allocator.free(hash);
//         try builder.addData(hash);
//         std.debug.print("  {}. {s}\n", .{ i + 1, data });
//     }

//     // Build the tree
//     var tree = try builder.build();
//     defer tree.deinit();

//     const root_hash = tree.getRoot();
//     const root_hex = try merkle.hashToHex(allocator, root_hash);
//     defer allocator.free(root_hex);

//     std.debug.print("\nMerkle Root (hex): {s}\n", .{root_hex});
//     std.debug.print("Root hash length: {} bytes\n", .{root_hash.len});

//     // Demonstrate with different data
//     std.debug.print("\n=== Comparing with different data ===\n", .{});

//     var builder2 = merkle.MerkleTreeBuilder.init(allocator);
//     defer builder2.deinit();

//     const different_data = [_][]const u8{
//         "Transaction 1: Alice sends 10 BTC to Bob",
//         "Transaction 2: Bob sends 5 BTC to Charlie",
//         "Transaction 3: Charlie sends 3 BTC to Dave",
//         "Transaction 4: Dave sends 2 BTC to Eve", // Changed amount
//     };

//     for (different_data) |data| {
//         const hash = try merkle.hashData(allocator, data);
//         defer allocator.free(hash);
//         try builder2.addData(hash);
//     }

//     var tree2 = try builder2.build();
//     defer tree2.deinit();

//     const root_hash2 = tree2.getRoot();
//     const root_hex2 = try merkle.hashToHex(allocator, root_hash2);
//     defer allocator.free(root_hex2);

//     std.debug.print("Original root:  {s}\n", .{root_hex});
//     std.debug.print("Modified root:  {s}\n", .{root_hex2});
//     std.debug.print("Roots are equal: {}\n", .{std.mem.eql(u8, root_hash, root_hash2)});

//     // Demonstrate utility function
//     std.debug.print("\n=== Using utility function ===\n", .{});
// }

// Simple CSV loader for format:
// stageIndex,leafIndex,account,amount
// 0,0,0x...,57025514540855960000000
// Returns array of Row with each field stored as an owned string slice.

// A CSV row: list of owned (heap-duped) column byte slices.
const Row = struct {
    values: std.ArrayList([]u8),
};

// Frees all allocated memory held by the rows list (including each column slice).
pub fn freeRows(allocator: std.mem.Allocator, rows: *std.ArrayList(Row)) void {
    for (rows.items) |*r| {
        // Free each column slice we duplicated.
        for (r.values.items) |col| allocator.free(col);
        r.values.deinit(allocator);
    }
    rows.deinit(allocator);
}

fn loadCsv(allocator: std.mem.Allocator, path: []const u8) !std.ArrayList(Row) {
    var file = try std.fs.cwd().openFile(path, .{});
    defer file.close();

    var buffer : [1024]u8 = undefined;

    // var reader = &(file.reader(&buffer).interface);
    var reader = file.reader(&buffer);
    var interface = &reader.interface;

    var rows = std.ArrayList(Row){};
    errdefer freeRows(allocator, &rows);

    while (true) {
        const line_or_err = interface.takeDelimiterExclusive('\n');
        if (line_or_err) |line| {
            // Ignore completely empty lines
            if (std.mem.trim(u8, line, " \t").len == 0) continue;
            var cols = std.mem.splitScalar(u8, line, ',');
            var cols_values = std.ArrayListUnmanaged([]u8){};
            try cols_values.append(allocator, try allocator.dupe(u8, "1"));
            while (cols.next()) |col| {
                const trimmed = std.mem.trim(u8, col, " \t");
                const owned = try allocator.dupe(u8, trimmed);
                try cols_values.append(allocator, owned);
            }
            try rows.append(allocator, Row { .values = cols_values });
        } else |err| switch (err) {
            error.EndOfStream => break, // normal termination
            error.StreamTooLong,
            error.ReadFailed,
            => |e| return e,
        }
    }
    return rows;
}

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.c_allocator);
    defer arena_state.deinit();
    // var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    // defer _ = gpa.deinit();
    // const allocator = gpa.allocator();
    const allocator = arena_state.allocator();

    // Allow path override via command line arg; default to data/airdrop-list.csv
    var args_iter = try std.process.argsWithAllocator(allocator);
    defer args_iter.deinit();
    _ = args_iter.next(); // skip program name
    const path = args_iter.next() orelse "data/batch1.csv";

    std.debug.print("Loading CSV: {s}\n", .{path});
    const start = try std.time.Instant.now();
    var rows = try loadCsv(allocator, path);
    defer freeRows(allocator, &rows);
    const end = try std.time.Instant.now();

    std.debug.print("Loaded {} rows in {} ms\n", .{ rows.items.len, @divTrunc(end.since(start), std.time.ns_per_ms) });

    // Print first few rows as a sanity check
    const preview = @min(rows.items.len, 5);
    std.debug.print("First {} rows:\n", .{preview});
    for (rows.items[0..preview]) |r| {
        for (r.values.items, 0..) |col, i| {
            std.debug.print("{s}", .{ col });
            if (i + 1 < r.values.items.len) std.debug.print(",", .{});
        }
        std.debug.print("\n", .{});
    }

    var row_vec = std.ArrayList([][]u8){};
    defer {
        row_vec.deinit(allocator);
    }
    for (rows.items) |r| {
        try row_vec.append(allocator, r.values.items);
    }

    std.debug.print("building the merkle tree\n", .{});
    var leave_encoding = [_][]const u8{
        "uint256",
        "uint256" ,
        "uint256" ,
        "address" ,
        "uint256" ,
    };

    const start2 = try std.time.Instant.now();
    var tree = try merkle.StandardMerkleTree.of(allocator, row_vec.items[1..], leave_encoding[0..]);

    const end2 = try std.time.Instant.now();
    std.debug.print("built in {} ms\n", .{ @divTrunc(end2.since(start2), std.time.ns_per_ms) });
    const root = try merkle.hashToHex(allocator, tree.root());
    defer allocator.free(root);
    std.debug.print("Merkle Root (hex): {s}\n", .{root});

    defer tree.deinit();
}