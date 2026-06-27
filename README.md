# zk-HM (ZKBoo + Halevi–Micali Commitments)

This repository implements a **ZKBoo-style proof of SHA-256 preimage knowledge**, adapted to **statistically hiding Halevi–Micali (HM) commitments**.

It extends the MPC-in-the-head SHA-256 proof by:
- supporting **arbitrary-length inputs** (multiple SHA-256 rounds),
- integrating a **universal hashing step**,
- enabling a proof of knowledge of the preimage of a **statistically-hiding HM commitment** (using SHA-256 as the collision-resistant function).


## Build

### Requirements

- C compiler (C11)
- CMake ≥ 3.16
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
