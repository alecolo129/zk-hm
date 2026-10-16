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

### Plain HM commitments

The public API is declared in `include/hm.h`.

The library supports plain HM commitments of bit-string messages. 
Plain HM commitments can share one Toeplitz matrix across a batch of
equally-sized messages, reducing the communication overhead.

A typical flow is:

1. call `hm_commit_get_sizes()` to obtain the required sizes for the caller-owned buffers;
2. allocate buffers for *commitment* and *opening* using the sizes obtained in Setp 1;
3. call `hm_context_create()` to create sender's context which includes a random Toeplitz. In case of batch commitments, a single context is reused for the entire batch;
4. call `hm_commit()` with the sender's context to sample a fresh *opening* and generates a *commitment* for the input message.
5. export the public matrix with `hm_context_export_matrix()` and send it to the receiver. The receiver calls `hm_context_from_matrix()` to create his own context from the public matrix.
6. call `hm_verify()` with the receiver's context to verify the *commitment* against the input *message* and revealed *opening*.


### HM (bit-)commitments with Zero-Knowledge verification

For bit-commitments, the library also provides zero-knowledge proofs of pre-image knowledge.
A typical zero-knowledge bit-commitment flow is:
1. call `hm_bit_commit()` to commit to a *bit*, producing a *commitment*, an *opening*, and a *proof file*;
2. call `hm_bit_verify()` to verify the *proof file* against the input *bit* and *commitment*;
3. release library-owned buffers with `hm_buffer_free()`.

C and C++ examples are available in `examples/` and are disabled by default:

```bash
./build.sh -e
# plain HM commitments 
./build/examples/hm_commit_batch_c
./build/examples/hm_commit_batch_cpp
# zk HM bit-commitments
./build/examples/hm_bit_commit_c
./build/examples/hm_bit_commit_cpp
```

## Benchmarks

Plain Halevi-Micali commitment benchmarks are disabled by default. Build and run them with:

```bash
./build.sh -b
./build/benchmarks/hm_plain_benchmark
```

The scalar benchmarks cover power-of-two message lengths from 1 through 1024 bits:

- `BM_PlainCommit`: commit using a prepared context.
- `BM_PlainVerify`: verify using a separate context imported from the public matrix.
- `BM_PlainContextCreate`: measure allocation and uniform matrix sampling.

`BM_PlainCommitBatch` measures batches of 1,000, 100,000, and 1,000,000 two-bit commitments, with one new context per batch. Its counters report:

- `allocation_ms`: construction of the commitment and opening buffers;
- `setup_ms`: context allocation and matrix sampling;
- `commitment_ms`: generation of all commitments using the shared context;
- `total_ms`: the sum of these three stages.

`matrix_bytes` reports the shared matrix size. `commitment_bytes` and
`opening_bytes` are per-message sizes.

Note: a batch transmits `matrix_bytes + batch_size * commitment_bytes` bytes before opening.

For five repetitions with aggregate JSON output:

```bash
./build/benchmarks/hm_plain_benchmark \
  --benchmark_repetitions=5 \
  --benchmark_report_aggregates_only=true \
  --benchmark_out=hm_plain_benchmark.json \
  --benchmark_out_format=json
```

An bench run for commit c130285ffb4ed1eba9dbf3a387c1ce39035c2b82 (GCC 13.3.0, OpenSSL 3.0.13, release benchmark library) gave these
medians over ten repetitions:

| Two-bit operation | Median time |
| --- | ---: |
| Commit with prepared context | 0.793 µs |
| Verify with prepared context | 0.315 µs |
| Batch of 1,000, including allocation and setup | 0.759 ms |
| Batch of 100,000, including allocation and setup | 79.715 ms |
| Batch of 1,000,000, including allocation and setup | 822.250 ms |
