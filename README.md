# zk-HM (ZKBoo + Halevi–Micali Commitments)

This repository implements a **ZKBoo-style proof of SHA-256 preimage knowledge**, adapted to **statistically hiding Halevi–Micali (HM) commitments** (using SHA-256 as the collision-resistant function).

It extends the MPC-in-the-head SHA-256 proof by supporting **arbitrary-length inputs** (multiple SHA-256 rounds), and integrating a **universal hashing step**.


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

A typical zero-knowledge bit-commitment flow is:
1. call `hm_bit_commit()` to create a commitment, opening, and proof file;
2. call `hm_bit_verify()` to verify the proof file against the commitment;
3. release library-owned buffers with `hm_buffer_free()`.

In the non zero-knowledge setting (where the opening is also known), the verifier can just call `hm_bit_open()`, which directly verifies the halevi-micali commitment against the opening and the input bit.


C and C++ examples are available in `examples/` and are disabled by default:

```bash
./build.sh -e
./build/examples/hm_bit_commit_c
./build/examples/hm_bit_commit_cpp
```
