# Merkle Tree Zig

A simple and educational implementation of a Merkle Tree (binary hash tree) in Zig.

## What is a Merkle Tree?

A Merkle Tree is a binary tree where:
- Every leaf node contains the hash of a data block
- Every non-leaf node contains the hash of its child nodes
- The root represents a single hash that summarizes all the data

Merkle Trees are widely used in blockchain technology, distributed systems, and version control systems like Git.

## Features

- ✅ Basic Merkle Tree implementation
- ✅ SHA-256 hashing
- ✅ Memory-safe with proper cleanup
- ✅ Comprehensive tests
- ✅ Example usage
- ✅ Benchmarking tools
- ✅ Documentation generation

## Project Structure

```
merkle-tree-zig/
├── build.zig          # Build configuration
├── src/
│   └── lib.zig        # Main library implementation
├── examples/
│   └── main.zig       # Usage examples
├── benchmark/
│   └── main.zig       # Performance benchmarks
└── README.md          # This file
```

## Usage

### Testing and Running

```bash
# Run tests (main way to test the library)
zig test src/lib.zig
# or use the build system:
zig build test

# Run the example
zig run examples/main.zig

# Run simple benchmark
zig run benchmark/simple_benchmark.zig

# Format code
zig fmt src/lib.zig

# Build and run benchmarks
zig build benchmark
./zig-out/bin/benchmark

# Generate documentation
zig build docs
```

### Using the Library

For now, you can copy the `MerkleTree` implementation from `src/lib.zig` into your project, or include the file directly. The example in `examples/main.zig` shows how to use it.

### Basic Example

```zig
const std = @import("std");
// Import the library (copy MerkleTree struct or include src/lib.zig)

pub fn main() !void {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer _ = gpa.deinit();
    const allocator = gpa.allocator();

    // Create a new Merkle Tree
    var tree = MerkleTree.init(allocator);
    defer tree.deinit();

    // Add data
    try tree.addData("Hello");
    try tree.addData("World");
    try tree.addData("Merkle");
    try tree.addData("Tree");

    // Get the root hash
    const root = try tree.getRoot();
    const root_hex = try tree.hashToHex(root);
    defer allocator.free(root_hex);

    std.debug.print("Merkle Root: {s}\n", .{root_hex});
}
```

## API Reference

### MerkleTree

#### Methods

- `init(allocator: std.mem.Allocator) MerkleTree` - Initialize a new tree
- `deinit(*MerkleTree) void` - Clean up and free memory
- `addData(*MerkleTree, []const u8) !void` - Add data to the tree
- `getRoot(*MerkleTree) ![]const u8` - Get the root hash (builds tree if needed)
- `hashToHex(*MerkleTree, []const u8) ![]const u8` - Convert hash to hex string

#### Utility Functions

- `createMerkleTree(allocator, data_items) !MerkleTree` - Create tree from data slice

## Performance

The implementation uses SHA-256 for hashing and is optimized for educational clarity rather than maximum performance. Benchmarks are included to measure performance characteristics.

## Testing

Run the test suite with:

```bash
zig build test
```

Tests cover:
- Basic tree functionality
- Single item trees
- Empty tree handling
- Utility functions
- Memory management

## Contributing

This is an educational project. Feel free to:
- Add more hash algorithms
- Implement Merkle proofs
- Add more comprehensive benchmarks
- Improve documentation

## License

This project is released under the MIT License. See the source code for details.

## Educational Resources

- [Merkle Tree on Wikipedia](https://en.wikipedia.org/wiki/Merkle_tree)
- [How Merkle Trees Work (Bitcoin Wiki)](https://en.bitcoin.it/wiki/Protocol_documentation#Merkle_Trees)
- [Understanding Merkle Trees](https://www.geeksforgeeks.org/introduction-to-merkle-tree/)