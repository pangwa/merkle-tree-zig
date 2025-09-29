const std = @import("std");
const merkle = @import("merkle-tree-zig");

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

      // Create or open a file for writing
    var file = try std.fs.cwd().createFile("data/tree.json", .{});
    defer file.close();
    var buffer: [1024]u8 = undefined;
    var writer = file.writer(&buffer);

    try tree.dumpJson(allocator, &writer.interface);
}