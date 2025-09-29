const zabi = @import("zabi");
const std = @import("std");
const testing = @import("std").testing;
const core = @import("core.zig");

const ParamType = zabi.abi.param_type.ParamType;
const encodeAbiParametersValues = zabi.encoding.abi_encoding.encodeAbiParametersValues;
const AbiEncodedValues = zabi.encoding.abi_encoding.AbiEncodedValues;
const utils = zabi.utils.utils;
const hashToHex = core.hashToHex;
const TokensTag = zabi.human_readable.TokensTag;

const LeafValue = []const u8;

const HashedValues = struct {
    value: [] const LeafValue,
    value_index: usize,
    hash: []const u8,

    const Self = @This();

    pub fn dupe(self: *const Self, allocator: std.mem.Allocator) !Self {
        const value = try dupeNestedSlice(allocator, self.value);
        errdefer {
            for (value) |v| allocator.free(v);
            allocator.free(value);
        }
        const hash = try allocator.dupe(u8, self.hash);

        return Self{
            .value = value,
            .hash = hash,
            .value_index = self.value_index,
        };
    }

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (0..self.value.len) |i| {
            allocator.free(self.value[i]);
        }
        allocator.free(self.value);
        allocator.free(self.hash);
    }
};

pub const StandardMerkleTree = struct {
    format: []u8,
    tree: core.MerkleTree,
    values: std.ArrayList(HashedValues),
    leaf_encoding: [][] const u8,
    allocator: std.mem.Allocator,

    const Self = @This();

    pub fn deinit(self: *Self) void {
        self.allocator.free(self.format);
        self.tree.deinit();

        for(0..self.values.items.len) |i| {
            self.values.items[i].deinit(self.allocator);
        }
        self.values.deinit(self.allocator);
    }

    pub fn of(allocator: std.mem.Allocator, leaves: []const []const LeafValue, leave_encoding: [][]const u8) ! StandardMerkleTree{
        var start = try std.time.Instant.now();
        const param_types = try allocator.alloc(ParamType, leave_encoding.len);
        var allocated_param_types: usize = 0;
        defer {
            for (param_types[0..allocated_param_types]) |pt| {
                pt.freeArrayParamType(allocator);
            }
            allocator.free(param_types);
        }
        for (leave_encoding, 0..) |enc, i| {
            const token_tag = TokensTag.typesKeyword(enc) orelse return error.InvalidTokenType;
            param_types[i] = zabi.abi.param_type.ParamType.fromHumanReadableTokenTag(token_tag) orelse return error.InvalidParamType;
            allocated_param_types += 1;
        }

        var values = std.ArrayList(HashedValues){};
        // defer values.deinit(allocator);
        errdefer {
            for (0..values.items.len) |i| {
                values.items[i].deinit(allocator);
            }
            values.deinit(allocator);
        }

        for (leaves, 0..) |leaf, i| {
            const hash = try standardLeafHash(allocator, leaf, param_types);
            try values.append(allocator, .{
                .value = try dupeNestedSlice(allocator, leaf),
                .value_index = i,
                .hash = hash,
            });
        }

        std.mem.sort(HashedValues, values.items[0..], {}, struct {
            fn lessThan(context: void, a: HashedValues, b: HashedValues) bool {
                _ = context;
                return std.mem.order(u8, a.hash, b.hash) == .lt;
            }
        }.lessThan);

        var encoded_leaves = std.ArrayList([] const u8){};
        defer encoded_leaves.deinit(allocator);

        for (0..values.items.len) |i| {
            values.items[i].value_index = i;
            try encoded_leaves.append(allocator, values.items[i].hash);
        }

        start = try std.time.Instant.now();

        var tree_builder = core.MerkleTreeBuilder.init(allocator);
        defer tree_builder.deinit();
        try tree_builder.addBatchData(encoded_leaves.items);

        const tree = try tree_builder.build();
        return StandardMerkleTree {
            .allocator = allocator,
            .format = try allocator.dupe(u8, "standard-v1"),
            .tree = tree,
            .values = values,
            .leaf_encoding = leave_encoding,
        };
    }

    pub fn root(self: *Self) []const u8 {
        return self.tree.root;
    }

    pub fn treeNodes(self: *Self) [][]const u8 {
        return self.tree.tree_nodes;
    }

    /// Write the JSON representation of the merkle tree to any writer.
    /// Caller owns the writer (file, fixed buffer, ArrayList writer, etc.).
    /// No implicit file creation is performed here.
    pub fn dumpJson(self: *Self, allocator: std.mem.Allocator, writer: anytype) !void {
        // Build a transient representation suitable for std.json formatting
        var tree_data = try StandardMerkleTreeData.from(allocator, self);
        defer tree_data.deinit(allocator);

        const fmt = std.json.fmt(tree_data, .{ .whitespace = .indent_2 });
        try fmt.format(writer);
        // Most writers (FixedBufferStream, ArrayList) don't require an explicit flush.
    }
};


const StandardMerkleTreeData = struct {
    format: []u8,
    values: []HashedValuesJson,
    leaf_encoding: [][]const u8,
    root: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        allocator.free(self.format);

        for(0..self.values.len) |i| {
            self.values[i].deinit(allocator);
        }
        allocator.free(self.values);

        for (0..self.leaf_encoding.len) |i| {
            allocator.free(self.leaf_encoding[i]);
        }
        allocator.free(self.leaf_encoding);
        allocator.free(self.root);
    }

    pub fn from(allocator: std.mem.Allocator, tree: *StandardMerkleTree) !Self {
        const format = try allocator.dupe(u8, tree.format);
        const root = try hashToHex(allocator, tree.root());
        defer allocator.free(root);

        var values = try renderHashedValues(allocator, tree.values.items);
        defer values.deinit(allocator);
        errdefer {
            for (0..values.items.len) |i| {
                values.items[i].deinit(allocator);
            }
        }

        const leaf_encoding = try allocator.alloc([]const u8, tree.leaf_encoding.len);
        for (tree.leaf_encoding, 0..) |le, i| {
            leaf_encoding[i] = try allocator.dupe(u8, le);
        }

        return Self{
            .format = format,
            .values = try allocator.dupe(HashedValuesJson, values.items),
            .leaf_encoding = leaf_encoding,
            .root = try allocator.dupe(u8, root),
        };
    }
};

// JSON representation of a hashed value
const HashedValuesJson = struct {
    value: [][]const u8,
    value_index: usize,
    hash: []const u8,

    const Self = @This();

    pub fn deinit(self: *Self, allocator: std.mem.Allocator) void {
        for (0..self.value.len) |i| {
            allocator.free(self.value[i]);
        }
        allocator.free(self.value);
        allocator.free(self.hash);
    }

    pub fn fromHashedValues(allocator: std.mem.Allocator, hv: HashedValues) !Self {
        const value = try dupeNestedSlice(allocator, hv.value);
        errdefer {
            for (value) |v| allocator.free(v);
            allocator.free(value);
        }
        const hash = try hashToHex(allocator, hv.hash);

        return Self{
            .value = value,
            .hash = hash,
            .value_index = hv.value_index,
        };
    }
};

fn renderHashedValues(allocator: std.mem.Allocator, hv: []HashedValues) !std.ArrayList(HashedValuesJson){
    var renderedValues = std.ArrayList(HashedValuesJson){};
    errdefer {
        for (0..renderedValues.items.len) |i| {
            renderedValues.items[i].deinit(allocator);
        }
        renderedValues.deinit(allocator);
    }

    for (hv) |h| {
        var hashed_value = try HashedValuesJson.fromHashedValues(allocator, h);
        errdefer hashed_value.deinit(allocator);
        try renderedValues.append(allocator, hashed_value);
    }
    return renderedValues;
}

fn dupeNestedSlice(allocator: std.mem.Allocator, original: []const []const u8) ![][]const u8 {
    // Allocate memory for the outer slice (array of slices)
    const new_outer_slice = try allocator.alloc([]const u8, original.len);
    errdefer allocator.free(new_outer_slice); // Clean up if errors occur during nested allocation

    // Iterate and duplicate each inner slice
    for (original, 0..) |inner_slice, i| {
        // Allocate memory for the current inner slice and copy its contents
        const new_inner_slice = try allocator.dupe(u8, inner_slice);
        errdefer {
            // Free previously duplicated inner slices if an error occurs
            for (new_outer_slice[0..i]) |prev_inner| allocator.free(prev_inner);
            allocator.free(new_outer_slice);
        }
        new_outer_slice[i] = new_inner_slice;
    }

    return new_outer_slice;
}

fn parseSimpleValue(value: []const u8, param_type: ParamType) !AbiEncodedValues {
    return switch (param_type) {
        .address => {
            const v = try utils.addressToBytes(value);
            return .{ .address = v };
        },
        .bool => {
            const v = std.mem.eql(u8, value, "true");
            return .{ .bool = v };
        },
        .uint => {
            const v = try std.fmt.parseUnsigned(u256, value, 10);
            return .{ .uint = v };
        },
        .string => {
            return .{ .string = value };
        },
        .bytes => {
            return .{ .bytes = value };
        },
        .int => {
            const v = try std.fmt.parseInt(i256, value, 10);
            return .{ .int = v };
        },
        .fixedBytes => {
            return .{ .bytes = value };
        },
        .fixedArray => {
            return .{ .bytes = value };
        },
        else => {
            std.debug.print("type not supported yet: {}\n", .{param_type});
            return error.UnsupportedParamType;
        },
    };
}

fn standardLeafHash(allocator: std.mem.Allocator, leaf: []const LeafValue, param_types: []const ParamType) ![]u8 {
    if (leaf.len != param_types.len) {
        std.debug.print("leaf length {} does not match param_types length {}\n", .{ leaf.len, param_types.len });
        return error.InvalidValueCount;
    }
    const values = try allocator.alloc(AbiEncodedValues, leaf.len);
    defer allocator.free(values);
    for (leaf, param_types, 0..) |l, pt, i| {
        values[i] = try parseSimpleValue(l, pt);
    }
    const leaf_encoded = try encodeAbiParametersValues(allocator, values);
    defer allocator.free(leaf_encoded);

    var hash_result = allocator.alloc(u8, 32) catch {
        return error.OutOfMemory;
    };

    // Note: double hash to prevent second pre-image attack
    std.crypto.hash.sha3.Keccak256.hash(leaf_encoded, hash_result[0..32], .{});
    std.crypto.hash.sha3.Keccak256.hash(hash_result, hash_result[0..32], .{});
    return hash_result;
}

fn buildTreeFromCharacters(allocator: std.mem.Allocator, s: []const u8) !StandardMerkleTree{
    var arena = std.heap.ArenaAllocator.init(allocator);
    var local_alloc = arena.allocator();
    defer arena.deinit(); // Frees everything at once
    var items = std.ArrayList([][]u8){};

    for (s) |c| {
        const r = try local_alloc.alloc([]u8, 1);
        r[0] = try local_alloc.dupe(u8, &[_]u8{c});
        try items.append(local_alloc, r);
    }

    var leave_encoding = [_][]const u8{"string"};
    const tree = try StandardMerkleTree.of(allocator, items.items[0..], leave_encoding[0..]);
    return tree;
}

test "abi encode" {
    const output = try encodeAbiParametersValues(testing.allocator, &.{.{ .address = try utils.addressToBytes("0xc0ffee254729296a45a3885639AC7E10F9d54979") }});
    defer testing.allocator.free(output);

    const hex = try hashToHex(testing.allocator, output);
    defer testing.allocator.free(hex);
    try testing.expectEqualStrings("000000000000000000000000c0ffee254729296a45a3885639ac7e10f9d54979", hex);
}

test "standard leaf hash" {
    const leaf = &[_]LeafValue{ "0x1111111111111111111111111111111111111111", "5000000000000000000" };
    const param_types = &[_]ParamType{ .address, .{ .uint = 256 } };
    const hash = try standardLeafHash(testing.allocator, leaf, param_types);
    defer testing.allocator.free(hash);
    const hex = try hashToHex(testing.allocator, hash);
    defer testing.allocator.free(hex);
    try testing.expectEqualStrings("eb02c421cfa48976e66dfb29120745909ea3a0f843456c263cf8f1253483e283", hex);
}

test "create standard merkle tree using of" {
    var leaves = [_][]const LeafValue{
        &[_]LeafValue{ "0x1111111111111111111111111111111111111111", "5000000000000000000" },
        &[_]LeafValue{ "0x2222222222222222222222222222222222222222", "2500000000000000000" },
    };
    var leave_encoding = [_][]const u8{ "address", "uint256" };
    var tree = try StandardMerkleTree.of(testing.allocator, leaves[0..], leave_encoding[0..]);
    defer tree.deinit();

    const root = try hashToHex(testing.allocator, tree.root());
    defer testing.allocator.free(root);

    try testing.expectEqualSlices(u8, "d4dee0beab2d53f2cc83e567171bd2820e49898130a22622b10ead383e90bd77", root);

    const expected_nodes = [_][]const u8{
        "d4dee0beab2d53f2cc83e567171bd2820e49898130a22622b10ead383e90bd77",
        "eb02c421cfa48976e66dfb29120745909ea3a0f843456c263cf8f1253483e283",
        "b92c48e9d7abe27fd8dfd6b5dfdbfb1c9a463f80c712b66f3a5180a090cccafc",
    };
    try testing.expectEqual(3, tree.treeNodes().len);

    for (expected_nodes, tree.treeNodes()) |expected, actual| {
        const actual_hex = try hashToHex(testing.allocator, actual);
        defer testing.allocator.free(actual_hex);
        try testing.expectEqualSlices(u8, expected, actual_hex);
    }
}

test "from characters" {
    const s = "abcdef";
    var tree = try buildTreeFromCharacters(testing.allocator, s);
    defer tree.deinit();

    const root = try hashToHex(testing.allocator, tree.root());
    defer testing.allocator.free(root);
    try testing.expectEqualStrings("6deb52b5da8fd108f79fab00341f38d2587896634c646ee52e49f845680a70c8", root);

    try testing.expectEqual(11, tree.treeNodes().len);

    const expected_nodes = [_][]const u8{ "6deb52b5da8fd108f79fab00341f38d2587896634c646ee52e49f845680a70c8", "52426e0f1f65ff7e209a13b8c29cffe82e3acaf3dad0a9b9088f3b9a61a929c3", "fd3cf45654e88d1cc5d663578c82c76f4b5e3826bacaa1216441443504538f51", "8076923e76cf01a7c048400a2304c9a9c23bbbdac3a98ea3946340fdafbba34f", "965b92c6cf08303cc4feb7f3e0819c436c2cec17c6f0688a6af139c9a368707c", "eba909cf4bb90c6922771d7f126ad0fd11dfde93f3937a196274e1ac20fd2f5b", "c62a8cfa41edc0ef6f6ae27a2985b7d39c7fea770787d7e104696c6e81f64848", "9cf5a63718145ba968a01c1d557020181c5b252f665cf7386d370eddb176517b", "9c15a6a0eaeed500fd9eed4cbeab71f797cefcc67bfd46683e4d2e6ff7f06d1c", "9a4f64e953595df82d1b4f570d34c4f4f0cfaf729a61e9d60e83e579e1aa283e", "19ba6c6333e0e9a15bf67523e0676e2f23eb8e574092552d5e888c64a4bb3681" };
    for (expected_nodes, tree.treeNodes()) |en, tn| {
        const tn_hex = try hashToHex(testing.allocator, tn);
        defer testing.allocator.free(tn_hex);
        try testing.expectEqualStrings(en[0..], tn_hex[0..]);
    }
}

test "to hashed values json" {
    const s = "abcdef";
    var tree = try buildTreeFromCharacters(testing.allocator, s);
    defer tree.deinit();

    var hashed_value_json = try HashedValuesJson.fromHashedValues(testing.allocator, tree.values.items[0]);
    defer hashed_value_json.deinit(testing.allocator);

    try testing.expectEqual(0, hashed_value_json.value_index);
}

test "merkle tree data" {
    const s = "abcdef";
    var tree = try buildTreeFromCharacters(testing.allocator, s);
    defer tree.deinit();

    var tree_data = try StandardMerkleTreeData.from(testing.allocator, &tree);
    defer tree_data.deinit(testing.allocator);

    try testing.expectEqualStrings("6deb52b5da8fd108f79fab00341f38d2587896634c646ee52e49f845680a70c8", tree_data.root);

}

test "to_json" {
    const s = "abcdef";
    var tree = try buildTreeFromCharacters(testing.allocator, s);
    defer tree.deinit();

    var buffer: [2048]u8 = undefined;
    var w: std.Io.Writer = .fixed(&buffer);

    try tree.dumpJson(testing.allocator, &w);
    try testing.expectEqual('{', buffer[0]);
}