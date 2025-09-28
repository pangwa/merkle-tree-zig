const std = @import("std");
const core = @import("core.zig");
const standard_merkle_tree = @import("standard_merkle_tree.zig");

pub const MerkleTreeBuilder = core.MerkleTreeBuilder;
pub const MerkleTree = core.MerkleTree;
pub const hashData = core.hashData;
pub const hashToHex = core.hashToHex;
pub const StandardMerkleTree = standard_merkle_tree.StandardMerkleTree;

// Reference the test blocks by ensuring the modules are used
test {
    // This ensures that test blocks from imported modules are included
    std.testing.refAllDecls(@This());
    std.testing.refAllDecls(core);
    std.testing.refAllDecls(standard_merkle_tree);
}
