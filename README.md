# zk-HM (ZKBoo + Halevi–Micali Commitments)

This repository implements a **ZKBoo-style proof of SHA-256 preimage knowledge**, adapted to **statistically hiding Halevi–Micali (HM) commitments** (using SHA-256 as the collision-resistant function).

It extends the MPC-in-the-head SHA-256 proof by supporting **arbitrary-length inputs** (multiple SHA-256 rounds), and integrating a **universal hashing step**.

The repository also implements plain Halevi-Micali commitments for bit-string messages.

## Build

### Requirements

- C compiler (C11)
- CMake
- OpenSSL (tested with 3.0)
- OpenMP

### Compile

```bash
./build.sh
```

Tests are disabled by default. To build and run the C++ tests:

```bash
./build.sh -t
ctest --test-dir build --output-on-failure
```

### Compile with sanitizers (slower)

```bash
./build.sh -s
```

## Examples

The public API is declared in `include/hm.h`. 

The library supports plain HM commitments of bit-strings.
A typical HM commitment flow is:
1. call `hm_commit_get_sizes()` to obtain the required output sizes;
2. allocate caller-owned buffers for the *commitment* and *opening*;
3. call `hm_commit()` to write into those buffers;
4. call `hm_verify()` to verify the *commitment* against the input *message* and *opening*.

For batches, the caller can allocate contiguous commitment and opening arrays
once and pass an appropriately sized slice to each `hm_commit()` call.

For bit-commitments, the library also support zero-knowledge proofs of pre-image knwoledge.
A typical zero-knowledge bit-commitment flow is:
1. call `hm_bit_commit()` to commit to a *bit*, producing a *commitment*, an *opening*, and a *proof file*;
2. call `hm_bit_verify()` to verify the *proof file* against the input *bit* and *commitment*;
3. release library-owned buffers with `hm_buffer_free()`.

C and C++ examples are available in `examples/` and are disabled by default:

```bash
./build.sh -e
# plain HM commitments
./build/examples/hm_commit_c
./build/examples/hm_commit_cpp
# plain HM commitments with batch allocation
./build/examples/hm_commit_batch_c
./build/examples/hm_commit_batch_cpp
# zk HM bit-commitments
./build/examples/hm_bit_commit_c
./build/examples/hm_bit_commit_cpp
```
