# zk-HM (ZKBoo + Halevi–Micali Commitments)

This repository implements a **ZKBoo-style proof of SHA-256 preimage knowledge**, adapted to **statistically hiding Halevi–Micali (HM) commitments**.

It extends the MPC-in-the-head SHA-256 proof by:
- supporting **arbitrary-length inputs** (multiple SHA-256 rounds),
- integrating a **universal hashing step**,
- enabling a proof of knowledge of the preimage of a **statistically-hiding HM commitment** (using SHA-256 as the collision-resistant function).

---

## Features

- ✅ ZKBoo-style MPC proof for SHA-256 preimage knowledge  
- ✅ Extension to **multi-block (long message) SHA-256 inputs**  
- ✅ Integration of **Halevi–Micali statistically hiding commitments**  
- ✅ Universal-hash based proof of commitment opening  
- ✅ **Improved parallel execution (OpenMP)** including serialization/deserialization for faster proof generation  

---

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
### Compile with sanitizers (slower)

```bash
./build.sh -s
```

## Usage

### Prover

```bash
./build/bin/hm_prover
```

### Verifier

```bash
./build/bin/hm_verifier
```

The output file (i.e., zk proof) is named:
``
out<NUM_ROUNDS>.bin
``
