const std = @import("std");
const testing = std.testing;
const print = std.debug.print;

// a builder help to build the Merkle Tree
pub const MerkleTreeBuilder = struct {
    allocator: std.mem.Allocator,
    leaves: std.ArrayList([]const u8),

    const Self = @This();

    /// Initialize a new Merkle Tree Builder
    pub fn init(allocator: std.mem.Allocator) Self {
        return Self{
            .allocator = allocator,
            .leaves = std.ArrayList([]const u8){},
        };
    }

    /// Clean up the Merkle Tree Builder and free allocated memory
    pub fn deinit(self: *Self) void {
        for (self.leaves.items) |leaf| {
            self.allocator.free(leaf);
        }
        self.leaves.deinit(self.allocator);
    }

    /// Add data to the tree (will be hashed to create a leaf)
    pub fn addData(self: *Self, data: []const u8) !void {
        if (data.len != 32) {
            return error.InvalidLeafSize;
        }
        const data_copy = try self.allocator.dupe(u8, data);
        try self.leaves.append(self.allocator, data_copy);
    }

    /// Build the Merkle Tree and return it
    pub fn build(self: *Self) !MerkleTree {
        if (self.leaves.items.len == 0) {
            return error.EmptyTree;
        }

        const leaves_count = self.leaves.items.len;
        const tree_length = 2 * leaves_count - 1;

        // Allocate tree_nodes array
        var tree = try self.allocator.alloc([]const u8, tree_length);

        // Initialize with empty slices (will be filled later)
        for (tree) |*node| {
            node.* = &[_]u8{};
        }

        // Place leaves at the end of the tree (right-most positions)
        for (self.leaves.items, 0..) |leaf, i| {
            const leaf_copy = try self.allocator.dupe(u8, leaf);
            tree[tree_length - 1 - i] = leaf_copy;
        }

        // Build internal nodes from bottom up
        var i: usize = tree_length - leaves_count;
        while (i > 0) {
            i -= 1;
            const left_child = tree[leftChildIndex(i)];
            const right_child = tree[rightChildIndex(i)];
            tree[i] = try hashPair(self.allocator, left_child, right_child);
        }

        // Create the root
        const root = try self.allocator.dupe(u8, tree[0]);

        return MerkleTree{
            .allocator = self.allocator,
            .root = root,
            .tree_nodes = tree,
        };
    }
};

pub const MerkleTree = struct {
    allocator: std.mem.Allocator,
    root: []const u8,
    tree_nodes: [][]const u8,

    const Self = @This();

    /// Clean up the Merkle Tree and free allocated memory
    pub fn deinit(self: *Self) void {
        self.allocator.free(self.root);

        // Free each node's data
        for (self.tree_nodes) |node| {
            if (node.len > 0) { // Only free non-empty nodes
                self.allocator.free(node);
            }
        }
        // Free the array itself
        self.allocator.free(self.tree_nodes);
    }

    pub fn fromTreeNodes(allocator: std.mem.Allocator, nodes: [][]const u8) !Self {
        if (nodes.len == 0) {
            return error.EmptyInput;
        }
        if (!try isValidMerkleTree(allocator, nodes)) {
            return error.InvalidMerkleNode;
        }

        const tree_nodes = try allocator.alloc([]const u8, nodes.len);
        errdefer allocator.free(tree_nodes);

        // Copy the node data
        for (nodes, 0..) |node, i| {
            const node_copy = try allocator.dupe(u8, node);
            tree_nodes[i] = node_copy;
        }

        const root = try allocator.dupe(u8, nodes[0]);

        return Self{
            .allocator = allocator,
            .root = root,
            .tree_nodes = tree_nodes,
        };
    }

    /// Get the root hash
    pub fn getRoot(self: *const Self) []const u8 {
        return self.root;
    }

    pub fn isTreeNode(self: *const Self, idx: usize) bool {
        return idx < self.tree_nodes.len;
    }

    pub fn isInternalNode(self: *const Self, i: usize) bool {
        return self.isTreeNode(leftChildIndex(i));
    }

    pub fn isLeafNode(self: *const Self, i: usize) bool {
        return self.isTreeNode(i) and !self.isInternalNode(i);
    }

    pub fn getProof(self: *const Self, allocator: std.mem.Allocator, leaf_index: usize) ![][]const u8 {
        if (self.tree_nodes.len == 0) {
            return error.EmptyTree;
        }
        if (leaf_index >= self.tree_nodes.len) {
            return error.InvalidIndex;
        }

        if (!self.isLeafNode(leaf_index)) {
            return error.IndexIsNotLeaf;
        }

        var proof = std.ArrayList([]const u8){};

        var idx = leaf_index;

        while (idx > 0) {
            const sibling = try sibling_index(idx);
            const sibling_data = try allocator.dupe(u8, self.tree_nodes[sibling]);
            try proof.append(allocator, sibling_data);
            idx = parentIndex(idx);
        }

        return proof.toOwnedSlice(allocator);
    }
};

pub fn sibling_index(i: usize) !usize {
    if (i == 0) {
        return error.NoSibling; // Root has no sibling
    }
    if (i % 2 == 0) {
        return i - 1; // Right child
    } else {
        return i + 1; // Left child
    }
}

pub fn parentIndex(i: usize) usize {
    return (i - 1) / 2;
}

/// Hash a single piece of data using Keccak256
pub fn hashData(allocator: std.mem.Allocator, data: []const u8) ![]const u8 {
    var hash_bytes: [32]u8 = undefined;

    std.crypto.hash.sha3.Keccak256.hash(data, &hash_bytes, .{});
    return allocator.dupe(u8, &hash_bytes);
}

/// Hash a pair of nodes together
pub fn hashPair(allocator: std.mem.Allocator, left: []const u8, right: []const u8) ![]const u8 {
    var data = [_][]const u8{ left, right };
    std.mem.sort([]const u8, &data, {}, struct {
        fn lessThan(context: void, a: []const u8, b: []const u8) bool {
            _ = context;
            return std.mem.order(u8, a, b) == .lt;
        }
    }.lessThan);

    const concatenated = try std.mem.concat(allocator, u8, &data);
    defer allocator.free(concatenated);

    var hash_bytes: [32]u8 = undefined;
    std.crypto.hash.sha3.Keccak256.hash(concatenated, &hash_bytes, .{});

    return allocator.dupe(u8, &hash_bytes);
}

/// Convert hash bytes to hex string for display
pub fn hashToHex(allocator: std.mem.Allocator, hash: []const u8) ![]const u8 {
    const hex_chars = "0123456789abcdef";
    var hex_string = try allocator.alloc(u8, hash.len * 2);

    for (hash, 0..) |byte, i| {
        hex_string[i * 2] = hex_chars[byte >> 4];
        hex_string[i * 2 + 1] = hex_chars[byte & 0xf];
    }

    return hex_string;
}

pub fn hexToHash(allocator: std.mem.Allocator, hex: []const u8) ![]const u8 {
    if (hex.len % 2 != 0) {
        return error.InvalidHexLength;
    }

    const byte_len = hex.len / 2;
    var hash = try allocator.alloc(u8, byte_len);

    for (hex, 0..) |char, i| {
        const byte_index = i / 2;
        const is_high_nibble = (i % 2) == 0;

        const nibble = switch (char) {
            '0'...'9' => char - '0',
            'a'...'f' => char - 'a' + 10,
            'A'...'F' => char - 'A' + 10,
            else => return error.InvalidHexCharacter,
        };

        if (is_high_nibble) {
            hash[byte_index] = nibble << 4;
        } else {
            hash[byte_index] |= nibble;
        }
    }

    return hash;
}

/// Utility function to create a Merkle Tree from a slice of data
pub fn createMerkleTree(allocator: std.mem.Allocator, data_items: []const []const u8) !MerkleTree {
    if (data_items.len == 0) {
        return error.EmptyInput;
    }

    var builder = MerkleTreeBuilder.init(allocator);
    defer builder.deinit();

    for (data_items) |item| {
        try builder.addData(item);
    }

    return try builder.build();
}

/// Check if a node is a valid Merkle node (32 bytes)
fn isValidMerkleNode(node: []const u8) bool {
    return node.len == 32;
}

/// Get left child index for binary tree stored in array
fn leftChildIndex(parent_index: usize) usize {
    return 2 * parent_index + 1;
}

/// Get right child index for binary tree stored in array
fn rightChildIndex(parent_index: usize) usize {
    return 2 * parent_index + 2;
}

/// Validate if a tree structure represents a valid Merkle tree
pub fn isValidMerkleTree(allocator: std.mem.Allocator, tree: [][]const u8) !bool {
    if (tree.len == 0) {
        return false;
    }

    for (tree, 0..) |node, i| {
        if (!isValidMerkleNode(node)) {
            return false;
        }

        const l = leftChildIndex(i);
        const r = rightChildIndex(i);

        if (r >= tree.len) {
            if (l < tree.len) {
                return false;
            }
        } else {
            const expected_hash = try hashPair(allocator, tree[l], tree[r]);
            defer allocator.free(expected_hash);
            if (!std.mem.eql(u8, node, expected_hash)) {
                return false;
            }
        }
    }

    return true;
}

/// Process a Merkle proof to verify a leaf against a root
/// Takes a leaf hash and a proof (array of sibling hashes) and returns the computed root
pub fn processProof(allocator: std.mem.Allocator, leaf: []const u8, proof: [][]const u8) ![]const u8 {
    // Check if leaf is valid (32 bytes)
    if (leaf.len != 32) {
        return error.InvalidMerkleNode;
    }

    // Check if all proof elements are valid (32 bytes each)
    for (proof) |p| {
        if (p.len != 32) {
            return error.InvalidMerkleNode;
        }
    }

    // Start with the leaf and hash it with each proof element
    var current_hash: [32]u8 = undefined;
    @memcpy(&current_hash, leaf);

    for (proof) |proof_element| {
        const new_hash = try hashPair(allocator, &current_hash, proof_element);
        defer allocator.free(new_hash);
        @memcpy(&current_hash, new_hash);
    }

    return allocator.dupe(u8, &current_hash);
}

/// Create expected tree structure for testing
fn makeTree(allocator: std.mem.Allocator) !std.ArrayList([]const u8) {
    var tree = std.ArrayList([]const u8){};

    const node1 = [_]u8{
        115, 209, 118, 200, 5,  4,   69, 77, 194, 99,  240, 121, 27, 47, 159, 212, 239, 185,
        42,  0,   241, 72,  77, 142, 45, 32, 88,  158, 8,   61,  44, 11,
    };
    const node2 = [_]u8{
        206, 8,   250, 120, 108, 113, 57, 176, 105, 92,  78, 166, 155, 96,  168, 176, 157, 57,
        37,  199, 165, 0,   152, 41,  72, 109, 244, 215, 70, 159, 202, 146,
    };
    const node3 = [_]u8{
        230, 18,  175, 174, 238, 192, 61, 110, 232, 8,  30, 90, 33,  224, 209, 91, 37, 85,
        171, 114, 56,  219, 231, 210, 62, 217, 230, 42, 18, 28, 139, 203,
    };
    const node4 = [_]u8{
        233, 80,  165, 147, 77,  183, 162, 199, 17, 207, 58,  7,   225, 101, 161, 93, 18, 143,
        70,  211, 166, 76,  208, 229, 24,  100, 67, 52,  237, 111, 198, 96,
    };
    const node5 = [_]u8{
        15, 164, 23,  177, 133, 189, 185, 36, 130, 179, 11, 37,  19,  14, 240, 222, 25, 13,
        39, 28,  169, 28,  138, 102, 28,  45, 64,  166, 30, 143, 108, 92,
    };
    const node6 = [_]u8{
        233, 88,  165, 147, 77,  183, 162, 199, 170, 207, 58,  67,  225, 101, 161, 93, 18, 143,
        7,   211, 166, 76,  248, 229, 224, 113, 67,  52,  237, 131, 198, 96,
    };
    const node7 = [_]u8{
        157, 164, 23,  177, 133, 189, 185, 36, 130, 79,  11, 7,   190, 14, 240, 222, 55, 123,
        39,  238, 169, 228, 138, 102, 8,   45, 64,  166, 3,  143, 48,  92,
    };

    try tree.append(allocator, &node1);
    try tree.append(allocator, &node2);
    try tree.append(allocator, &node3);
    try tree.append(allocator, &node4);
    try tree.append(allocator, &node5);
    try tree.append(allocator, &node6);
    try tree.append(allocator, &node7);

    return tree;
}

test "hex to hash" {
    const hash = "e958a5934db7a2c7aacf3a43e165a15d128f07d3a64cf8e5e0714334ed83c660";
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();

    const allocator = gpa.allocator();

    const hash_bytes = try hexToHash(allocator, hash);
    const hex_string = try hashToHex(allocator, hash_bytes);

    defer allocator.free(hash_bytes);
    defer allocator.free(hex_string);

    try testing.expectEqualStrings(hash, hex_string);
}

test "hash pair" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const a = [_]u8{ 1, 2, 3, 4 };
    const b = [_]u8{ 2, 3, 5, 8 };
    const c = [_]u8{ 5, 6, 7, 8, 9, 10 };
    const d = [_]u8{ 0, 2, 3, 4 };

    const bytes = try hashPair(allocator, &a, &c);
    defer allocator.free(bytes);
    const bytes2 = try hashPair(allocator, &b, &d);
    defer allocator.free(bytes2);

    const expected_result = [_]u8{
        157, 164, 23,  177, 133, 189, 185, 36, 130, 79, 11,  7,  190, 14, 240, 222, 55, 123, 39,
        238, 169, 228, 138, 102, 8,   45,  64, 166, 3,  143, 48, 92,
    };
    const expected_result2 = [_]u8{
        233, 88,  165, 147, 77,  183, 162, 199, 170, 207, 58,  67,  225, 101, 161, 93, 18, 143, 7,
        211, 166, 76,  248, 229, 224, 113, 67,  52,  237, 131, 198, 96,
    };

    try testing.expectEqualSlices(u8, bytes, &expected_result);
    try testing.expectEqualSlices(u8, bytes2, &expected_result2);
}

test "make merkle tree" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const byte1 = [_]u8{
        157, 164, 23,  177, 133, 189, 185, 36, 130, 79, 11,  7,  190, 14, 240, 222, 55, 123, 39,
        238, 169, 228, 138, 102, 8,   45,  64, 166, 3,  143, 48, 92,
    };
    const byte2 = [_]u8{
        233, 88,  165, 147, 77,  183, 162, 199, 170, 207, 58,  67,  225, 101, 161, 93, 18, 143, 7,
        211, 166, 76,  248, 229, 224, 113, 67,  52,  237, 131, 198, 96,
    };
    const byte3 = [_]u8{
        15, 164, 23, 177, 133, 189, 185, 36, 130, 179, 11,  37,  19, 14, 240, 222, 25, 13, 39,
        28, 169, 28, 138, 102, 28,  45,  64, 166, 30,  143, 108, 92,
    };
    const byte4 = [_]u8{
        233, 80,  165, 147, 77,  183, 162, 199, 17, 207, 58,  7,   225, 101, 161, 93, 18, 143, 70,
        211, 166, 76,  208, 229, 24,  100, 67,  52, 237, 111, 198, 96,
    };

    const leaves = [_][]const u8{ &byte1, &byte2, &byte3, &byte4 };

    var tree = try createMerkleTree(allocator, &leaves);
    defer tree.deinit();

    const root = tree.getRoot();
    try testing.expect(root.len == 32); // Should produce a 32-byte hash

    const root_hex = try hashToHex(allocator, root);
    defer allocator.free(root_hex);
    try testing.expectEqualStrings(root_hex, "73d176c80504454dc263f0791b2f9fd4efb92a00f1484d8e2d20589e083d2c0b");

    var expected_tree = try makeTree(allocator);
    defer expected_tree.deinit(allocator);

    // Compare the number of nodes first
    try testing.expectEqual(tree.tree_nodes.len, expected_tree.items.len);

    for (tree.tree_nodes, expected_tree.items) |actual_node, expected_node| {
        try testing.expectEqualSlices(u8, actual_node, expected_node);
    }
}

// Tests
test "MerkleTree basic functionality" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var builder = MerkleTreeBuilder.init(allocator);
    defer builder.deinit();

    const data1 = try hashData(allocator, "Hello");
    const data2 = try hashData(allocator, "World");
    const data3 = try hashData(allocator, "Merkle");
    const data4 = try hashData(allocator, "Tree");
    defer allocator.free(data1);
    defer allocator.free(data2);
    defer allocator.free(data3);
    defer allocator.free(data4);

    try builder.addData(data1);
    try builder.addData(data2);
    try builder.addData(data3);
    try builder.addData(data4);

    var tree = try builder.build();
    defer tree.deinit();

    const root = tree.getRoot();
    try testing.expect(root.len == 32); // SHA-256 produces 32 bytes
}

test "MerkleTree single item" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var builder = MerkleTreeBuilder.init(allocator);
    defer builder.deinit();

    const data = try hashData(allocator, "SingleItem");
    defer allocator.free(data);

    try builder.addData(data);
    var tree = try builder.build();
    defer tree.deinit();

    const root = tree.getRoot();
    const hash = try hashToHex(allocator, root);
    defer allocator.free(hash);
    try testing.expect(root.len == 32);
}

test "MerkleTree empty tree" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var builder = MerkleTreeBuilder.init(allocator);
    defer builder.deinit();

    try testing.expectError(error.EmptyTree, builder.build());
}

test "get proof" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var expected_tree = try makeTree(allocator);
    defer expected_tree.deinit(allocator);
    var tree = try MerkleTree.fromTreeNodes(allocator, expected_tree.items);
    defer tree.deinit();

    const proof = try tree.getProof(allocator, 6);
    defer {
        for (proof) |item| {
            allocator.free(item);
        }
        allocator.free(proof);
    }

    const expectedProofs = [_][]const u8{
        "e958a5934db7a2c7aacf3a43e165a15d128f07d3a64cf8e5e0714334ed83c660",
        "ce08fa786c7139b0695c4ea69b60a8b09d3925c7a5009829486df4d7469fca92",
    };

    for (expectedProofs, 0..) |exp, idx| {
        const p = proof[idx];
        const p_hex = try hashToHex(allocator, p);
        defer allocator.free(p_hex);
        try testing.expectEqualStrings(exp, p_hex);
    }
}

test "process proof" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const leaf_hex = "9da417b185bdb924824f0b07be0ef0de377b27eea9e48a66082d40a6038f305c";
    const expected_root_hex = "73d176c80504454dc263f0791b2f9fd4efb92a00f1484d8e2d20589e083d2c0b";
    const proof_hex = [_][]const u8{ "e958a5934db7a2c7aacf3a43e165a15d128f07d3a64cf8e5e0714334ed83c660", "ce08fa786c7139b0695c4ea69b60a8b09d3925c7a5009829486df4d7469fca92" };

    // Convert hex strings to byte arrays
    const leaf = try hexToHash(allocator, leaf_hex);
    defer allocator.free(leaf);

    var proofs: [2][]const u8 = undefined;
    for (proof_hex, 0..) |hex, i| {
        proofs[i] = try hexToHash(allocator, hex);
    }
    defer {
        for (proofs) |proof| {
            allocator.free(proof);
        }
    }

    // Process the proof to get the root
    const computed_root = try processProof(allocator, leaf, &proofs);
    defer allocator.free(computed_root);
    const computed_root_hex = try hashToHex(allocator, computed_root);
    defer allocator.free(computed_root_hex);
    try testing.expectEqualStrings(computed_root_hex, expected_root_hex);
}

test "is valid merkle tree" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    var expected_tree = try makeTree(allocator);
    defer expected_tree.deinit(allocator);

    const is_valid = try isValidMerkleTree(allocator, expected_tree.items);
    try testing.expect(is_valid);

    // Test with empty tree
    const empty_tree: [][]const u8 = &[_][]const u8{};
    const is_empty_valid = try isValidMerkleTree(allocator, empty_tree);
    try testing.expect(!is_empty_valid);
}

test "createMerkleTree utility function" {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    const data = [_][]const u8{ "item1", "item2", "item3" };
    var hashed_data: [3][]const u8 = undefined;
    for (data, 0..) |item, i| {
        hashed_data[i] = try hashData(allocator, item);
    }
    defer {
        for (hashed_data) |item| {
            allocator.free(item);
        }
    }

    var tree = try createMerkleTree(allocator, &hashed_data);
    defer tree.deinit();

    const root = tree.getRoot();
    try testing.expect(root.len == 32);
}
