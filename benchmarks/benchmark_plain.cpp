#include "hm.h"

#include <benchmark/benchmark.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace {

using Context = std::unique_ptr<hm_context_t, decltype(&hm_context_free)>;
constexpr std::size_t kScalarFixtureCount = 1024;
constexpr std::size_t kBatchMessageBits = 2;

const char *compiler_version() {
#if defined(__clang__)
  return "Clang " __clang_version__;
#elif defined(__GNUC__)
  return "GCC " __VERSION__;
#else
  return "unknown";
#endif
}

void set_common_counters(benchmark::State &state, std::size_t bits,
                         const hm_commit_sizes_t &sizes) {
  state.counters["message_bits"] = static_cast<double>(bits);
  state.counters["commitment_bytes"] =
      static_cast<double>(sizes.commitment_len);
  state.counters["opening_bytes"] = static_cast<double>(sizes.opening_len);
  state.counters["matrix_bytes"] =
      static_cast<double>(sizes.toeplitz_matrix_len);
}

// All registered fixture sizes fit in RAND_bytes' int length argument.
bool random_messages(std::vector<uint8_t> &messages, std::size_t count,
                     std::size_t message_bytes) {
  messages.resize(count * message_bytes);
  return RAND_bytes(messages.data(), static_cast<int>(messages.size())) == 1;
}

enum class Operation { Commit, Verify };

template <Operation operation> void BM_PlainScalar(benchmark::State &state) {
  const auto bits = static_cast<std::size_t>(state.range(0));
  const std::size_t message_bytes = (bits + 7u) / 8u;
  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(bits, &sizes) != 0) {
    state.SkipWithError("invalid message length");
    return;
  }
  std::vector<uint8_t> messages;
  if (!random_messages(messages, kScalarFixtureCount, message_bytes)) {
    state.SkipWithError("random message generation failed");
    return;
  }
  std::vector<uint8_t> commitments(kScalarFixtureCount * sizes.commitment_len);
  std::vector<uint8_t> openings(kScalarFixtureCount * sizes.opening_len);
  hm_context_t *raw = nullptr;
  if (hm_context_create(bits, &raw) != 0) {
    state.SkipWithError("context creation failed");
    return;
  }
  Context sender(raw, hm_context_free);
  std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len);
  if (hm_context_export_matrix(sender.get(), matrix.data(), matrix.size()) !=
          0 ||
      hm_context_from_matrix(bits, matrix.data(), matrix.size(), &raw) != 0) {
    state.SkipWithError("matrix transfer failed");
    return;
  }
  Context receiver(raw, hm_context_free);
  for (std::size_t i = 0; i < kScalarFixtureCount; ++i) {
    const uint8_t *message = messages.data() + i * message_bytes;
    uint8_t *commitment = commitments.data() + i * sizes.commitment_len;
    uint8_t *opening = openings.data() + i * sizes.opening_len;
    if (hm_commit(sender.get(), message, commitment, sizes.commitment_len,
                  opening, sizes.opening_len) != 0 ||
        hm_verify(receiver.get(), message, commitment, sizes.commitment_len,
                  opening, sizes.opening_len) != 0) {
      state.SkipWithError("fixture correctness check failed");
      return;
    }
  }

  std::size_t index = 0;
  for (auto _ : state) {
    const uint8_t *message = messages.data() + index * message_bytes;
    uint8_t *commitment = commitments.data() + index * sizes.commitment_len;
    uint8_t *opening = openings.data() + index * sizes.opening_len;
    int result;
    if constexpr (operation == Operation::Verify) {
      result = hm_verify(receiver.get(), message, commitment,
                         sizes.commitment_len, opening, sizes.opening_len);
    } else {
      result = hm_commit(sender.get(), message, commitment,
                         sizes.commitment_len, opening, sizes.opening_len);
    }
    benchmark::DoNotOptimize(result);
    benchmark::ClobberMemory();
    if (result != 0) {
      state.SkipWithError("HM operation failed");
      break;
    }
    index = (index + 1u) % kScalarFixtureCount;
  }
  state.SetItemsProcessed(state.iterations());
  set_common_counters(state, bits, sizes);
}

// Isolate setup from commitment work; freeing is outside the manual duration.
void BM_PlainContextCreate(benchmark::State &state) {
  using Clock = std::chrono::steady_clock;
  const auto bits = static_cast<std::size_t>(state.range(0));
  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(bits, &sizes) != 0) {
    state.SkipWithError("invalid message length");
    return;
  }
  for (auto _ : state) {
    hm_context_t *raw = nullptr;
    const auto start = Clock::now();
    const int result = hm_context_create(bits, &raw);
    const auto end = Clock::now();
    Context ctx(raw, hm_context_free);
    state.SetIterationTime(std::chrono::duration<double>(end - start).count());
    benchmark::DoNotOptimize(ctx.get());
    if (result != 0) {
      state.SkipWithError("context creation failed");
      break;
    }
  }
  state.SetItemsProcessed(state.iterations());
  set_common_counters(state, bits, sizes);
}

void BM_PlainCommitBatch(benchmark::State &state) {
  using Clock = std::chrono::steady_clock;
  const auto count = static_cast<std::size_t>(state.range(0));
  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(kBatchMessageBits, &sizes) != 0) {
    state.SkipWithError("invalid message length");
    return;
  }
  std::vector<uint8_t> messages;
  if (!random_messages(messages, count, 1)) {
    state.SkipWithError("random message generation failed");
    return;
  }

  double allocation_seconds = 0;
  double setup_seconds = 0;
  double commitment_seconds = 0;
  for (auto _ : state) {
    const auto start = Clock::now();
    std::vector<uint8_t> commitments(count * sizes.commitment_len);
    std::vector<uint8_t> openings(count * sizes.opening_len);
    const auto allocated = Clock::now();
    hm_context_t *raw = nullptr;
    if (hm_context_create(kBatchMessageBits, &raw) != 0) {
      state.SkipWithError("context creation failed");
      break;
    }
    Context ctx(raw, hm_context_free);
    const auto prepared = Clock::now();
    bool failed = false;
    for (std::size_t i = 0; i < count; ++i) {
      if (hm_commit(ctx.get(), &messages[i],
                    commitments.data() + i * sizes.commitment_len,
                    sizes.commitment_len,
                    openings.data() + i * sizes.opening_len,
                    sizes.opening_len) != 0) {
        failed = true;
        break;
      }
    }
    const auto committed = Clock::now();
    allocation_seconds +=
        std::chrono::duration<double>(allocated - start).count();
    setup_seconds +=
        std::chrono::duration<double>(prepared - allocated).count();
    commitment_seconds +=
        std::chrono::duration<double>(committed - prepared).count();
    state.SetIterationTime(
        std::chrono::duration<double>(committed - start).count());
    benchmark::DoNotOptimize(commitments.data());
    benchmark::ClobberMemory();

    // Verify every coordinate outside the reported manual duration.
    if (!failed) {
      std::vector<uint8_t> matrix(sizes.toeplitz_matrix_len);
      failed = hm_context_export_matrix(ctx.get(), matrix.data(),
                                        matrix.size()) != 0 ||
               hm_context_from_matrix(kBatchMessageBits, matrix.data(),
                                      matrix.size(), &raw) != 0;
      Context receiver(failed ? nullptr : raw, hm_context_free);
      for (std::size_t i = 0; i < count && !failed; ++i) {
        failed = hm_verify(receiver.get(), &messages[i],
                           commitments.data() + i * sizes.commitment_len,
                           sizes.commitment_len,
                           openings.data() + i * sizes.opening_len,
                           sizes.opening_len) != 0;
      }
    }
    if (failed) {
      state.SkipWithError("batch correctness check failed");
      break;
    }
  }
  if (state.iterations() != 0) {
    const double ms_per_iteration =
        1000.0 / static_cast<double>(state.iterations());
    state.counters["allocation_ms"] = allocation_seconds * ms_per_iteration;
    state.counters["setup_ms"] = setup_seconds * ms_per_iteration;
    state.counters["commitment_ms"] = commitment_seconds * ms_per_iteration;
    state.counters["total_ms"] =
        (allocation_seconds + setup_seconds + commitment_seconds) *
        ms_per_iteration;
  }
  state.SetItemsProcessed(state.iterations() * static_cast<int64_t>(count));
  state.counters["batch_size"] = static_cast<double>(count);
  set_common_counters(state, kBatchMessageBits, sizes);
}

void register_benchmarks() {
  for (int64_t bits : {1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024}) {
    benchmark::RegisterBenchmark("BM_PlainCommit",
                                 BM_PlainScalar<Operation::Commit>)
        ->Arg(bits);
    benchmark::RegisterBenchmark("BM_PlainVerify",
                                 BM_PlainScalar<Operation::Verify>)
        ->Arg(bits);
    benchmark::RegisterBenchmark("BM_PlainContextCreate", BM_PlainContextCreate)
        ->Arg(bits)
        ->UseManualTime();
  }
  for (int64_t count : {1000, 100000, 1000000}) {
    benchmark::RegisterBenchmark("BM_PlainCommitBatch", BM_PlainCommitBatch)
        ->Arg(count)
        ->UseManualTime();
  }
}

} // namespace

int main(int argc, char **argv) {
  register_benchmarks();
  benchmark::AddCustomContext("Compiler", compiler_version());
  benchmark::AddCustomContext("OpenSSL", OpenSSL_version(OPENSSL_VERSION));
  benchmark::Initialize(&argc, argv);
  if (benchmark::ReportUnrecognizedArguments(argc, argv)) {
    return 1;
  }
  benchmark::RunSpecifiedBenchmarks();
  benchmark::Shutdown();
  return 0;
}
