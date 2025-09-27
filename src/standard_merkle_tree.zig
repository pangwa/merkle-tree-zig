const zabi = @import("zabi");
const std = @import("std");
const testing = @import("std").testing;
const core = @import("core.zig");

const ParamType = zabi.abi.param_type.ParamType;
const encodeAbiParametersValues = zabi.encoding.abi_encoding.encodeAbiParametersValues;
const utils = zabi.utils.utils;
const hashToHex = core.hashToHex;

test "abi encode" {
    const output = try encodeAbiParametersValues(testing.allocator, &.{
        .{ .address = try utils.addressToBytes("0xc0ffee254729296a45a3885639AC7E10F9d54979")}
    });
    defer testing.allocator.free(output);

    const hex = try hashToHex(testing.allocator, output);
    defer testing.allocator.free(hex);
    try testing.expectEqualStrings("000000000000000000000000c0ffee254729296a45a3885639ac7e10f9d54979", hex);
}
