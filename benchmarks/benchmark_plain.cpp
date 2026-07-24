#include "hm.h"

#include <benchmark/benchmark.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#include <chrono>
#include <climits>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <string>
#include <vector>

namespace {

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

std::size_t bits_to_bytes(std::size_t bit_len) {
  return bit_len / 8u + (bit_len % 8u != 0u);
}

bool checked_multiply(std::size_t left, std::size_t right,
                      std::size_t *result) {
  if (left != 0u && right > std::numeric_limits<std::size_t>::max() / left) {
    return false;
  }
  *result = left * right;
  return true;
}

bool fill_random(uint8_t *data, std::size_t len) {
  while (len != 0u) {
    const int chunk = len > static_cast<std::size_t>(INT_MAX)
                          ? INT_MAX
                          : static_cast<int>(len);
    if (RAND_bytes(data, chunk) != 1) {
      return false;
    }
    data += static_cast<std::size_t>(chunk);
    len -= static_cast<std::size_t>(chunk);
  }
  return true;
}

bool make_random_messages(std::vector<uint8_t> *messages,
                          std::size_t message_count,
                          std::size_t message_bit_len) {
  const std::size_t message_len = bits_to_bytes(message_bit_len);
  std::size_t messages_len = 0;
  if (!checked_multiply(message_count, message_len, &messages_len)) {
    return false;
  }

  messages->resize(messages_len);
  if (!fill_random(messages->data(), messages->size())) {
    return false;
  }

  const std::size_t used_bits = message_bit_len % 8u;
  if (used_bits != 0u) {
    const uint8_t mask = static_cast<uint8_t>((1u << used_bits) - 1u);
    for (std::size_t i = 0; i < message_count; ++i) {
      (*messages)[(i + 1u) * message_len - 1u] &= mask;
    }
  }
  return true;
}

void set_common_counters(benchmark::State &state, std::size_t message_bit_len,
                         const hm_commit_sizes_t &sizes) {
  state.counters["message_bits"] = static_cast<double>(message_bit_len);
  state.counters["commitment_bytes"] =
      static_cast<double>(sizes.commitment_len);
  state.counters["opening_bytes"] = static_cast<double>(sizes.opening_len);
}

void BM_PlainCommit(benchmark::State &state) {
  const std::size_t message_bit_len = static_cast<std::size_t>(state.range(0));
  const std::size_t message_len = bits_to_bytes(message_bit_len);

  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    state.SkipWithError("hm_commit_get_sizes failed");
    return;
  }

  std::vector<uint8_t> messages;
  if (!make_random_messages(&messages, kScalarFixtureCount, message_bit_len)) {
    state.SkipWithError("random message generation failed");
    return;
  }

  std::size_t commitments_len = 0;
  std::size_t openings_len = 0;
  if (!checked_multiply(kScalarFixtureCount, sizes.commitment_len,
                        &commitments_len) ||
      !checked_multiply(kScalarFixtureCount, sizes.opening_len,
                        &openings_len)) {
    state.SkipWithError("fixture size overflow");
    return;
  }

  std::vector<uint8_t> commitments(commitments_len);
  std::vector<uint8_t> openings(openings_len);
  std::size_t index = 0;

  for (auto _ : state) {
    const uint8_t *message = messages.data() + index * message_len;
    uint8_t *commitment = commitments.data() + index * sizes.commitment_len;
    uint8_t *opening = openings.data() + index * sizes.opening_len;

    int result = hm_commit(message, message_bit_len, commitment,
                           sizes.commitment_len, opening, sizes.opening_len);
    benchmark::DoNotOptimize(result);
    benchmark::ClobberMemory();
    if (result != 0) {
      state.SkipWithError("hm_commit failed");
      break;
    }
    index = (index + 1u) % kScalarFixtureCount;
  }

  state.SetItemsProcessed(state.iterations());
  set_common_counters(state, message_bit_len, sizes);
}

void BM_PlainVerify(benchmark::State &state) {
  const std::size_t message_bit_len = static_cast<std::size_t>(state.range(0));
  const std::size_t message_len = bits_to_bytes(message_bit_len);

  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(message_bit_len, &sizes) != 0) {
    state.SkipWithError("hm_commit_get_sizes failed");
    return;
  }

  std::vector<uint8_t> messages;
  if (!make_random_messages(&messages, kScalarFixtureCount, message_bit_len)) {
    state.SkipWithError("random message generation failed");
    return;
  }

  std::size_t commitments_len = 0;
  std::size_t openings_len = 0;
  if (!checked_multiply(kScalarFixtureCount, sizes.commitment_len,
                        &commitments_len) ||
      !checked_multiply(kScalarFixtureCount, sizes.opening_len,
                        &openings_len)) {
    state.SkipWithError("fixture size overflow");
    return;
  }

  std::vector<uint8_t> commitments(commitments_len);
  std::vector<uint8_t> openings(openings_len);
  for (std::size_t i = 0; i < kScalarFixtureCount; ++i) {
    const uint8_t *message = messages.data() + i * message_len;
    uint8_t *commitment = commitments.data() + i * sizes.commitment_len;
    uint8_t *opening = openings.data() + i * sizes.opening_len;
    if (hm_commit(message, message_bit_len, commitment, sizes.commitment_len,
                  opening, sizes.opening_len) != 0) {
      state.SkipWithError("verification fixture generation failed");
      return;
    }
  }

  std::size_t index = 0;
  for (auto _ : state) {
    const uint8_t *message = messages.data() + index * message_len;
    const uint8_t *commitment =
        commitments.data() + index * sizes.commitment_len;
    const uint8_t *opening = openings.data() + index * sizes.opening_len;

    int result = hm_verify(message, message_bit_len, commitment,
                           sizes.commitment_len, opening, sizes.opening_len);
    benchmark::DoNotOptimize(result);
    if (result != 0) {
      state.SkipWithError("hm_verify failed");
      break;
    }
    index = (index + 1u) % kScalarFixtureCount;
  }

  state.SetItemsProcessed(state.iterations());
  set_common_counters(state, message_bit_len, sizes);
}

void BM_PlainCommitBatch(benchmark::State &state) {
  using Clock = std::chrono::steady_clock;

  const std::size_t commitment_count = static_cast<std::size_t>(state.range(0));
  hm_commit_sizes_t sizes{};
  if (hm_commit_get_sizes(kBatchMessageBits, &sizes) != 0) {
    state.SkipWithError("hm_commit_get_sizes failed");
    return;
  }

  std::vector<uint8_t> messages;
  if (!make_random_messages(&messages, commitment_count, kBatchMessageBits)) {
    state.SkipWithError("random message generation failed");
    return;
  }

  std::size_t commitments_len = 0;
  std::size_t openings_len = 0;
  if (!checked_multiply(commitment_count, sizes.commitment_len,
                        &commitments_len) ||
      !checked_multiply(commitment_count, sizes.opening_len, &openings_len)) {
    state.SkipWithError("batch size overflow");
    return;
  }

  double allocation_seconds = 0.0;
  double commitment_seconds = 0.0;
  double total_seconds = 0.0;
  bool failed = false;

  for (auto _ : state) {
    const auto allocation_start = Clock::now();
    std::vector<uint8_t> commitments(commitments_len);
    std::vector<uint8_t> openings(openings_len);
    const auto commitment_start = Clock::now();

    for (std::size_t i = 0; i < commitment_count; ++i) {
      uint8_t *commitment =
          commitments.data() + i * sizes.commitment_len;
      uint8_t *opening = openings.data() + i * sizes.opening_len;
      if (hm_commit(&messages[i], kBatchMessageBits, commitment,
                    sizes.commitment_len, opening, sizes.opening_len) != 0) {
        state.SkipWithError("hm_commit failed");
        failed = true;
        break;
      }
    }

    const auto commitment_end = Clock::now();
    const double allocation_elapsed =
        std::chrono::duration<double>(commitment_start - allocation_start)
            .count();
    const double commitment_elapsed =
        std::chrono::duration<double>(commitment_end - commitment_start)
            .count();
    const double total_elapsed =
        std::chrono::duration<double>(commitment_end - allocation_start)
            .count();

    allocation_seconds += allocation_elapsed;
    commitment_seconds += commitment_elapsed;
    total_seconds += total_elapsed;
    state.SetIterationTime(total_elapsed);

    benchmark::DoNotOptimize(commitments.data());
    benchmark::DoNotOptimize(openings.data());
    benchmark::ClobberMemory();

    if (failed) {
      break;
    }
  }

  const double completed_iterations = static_cast<double>(state.iterations());
  if (completed_iterations != 0.0) {
    state.counters["allocation_ms"] =
        1000.0 * allocation_seconds / completed_iterations;
    state.counters["commitment_ms"] =
        1000.0 * commitment_seconds / completed_iterations;
    state.counters["total_ms"] = 1000.0 * total_seconds / completed_iterations;
  }
  state.SetItemsProcessed(state.iterations() *
                          static_cast<int64_t>(commitment_count));
  state.counters["batch_size"] = static_cast<double>(commitment_count);
  set_common_counters(state, kBatchMessageBits, sizes);
}

void register_scalar_benchmarks() {
  constexpr int64_t bit_lengths[] = {1,  2,   4,   8,   16,  32,
                                     64, 128, 256, 512, 1024};
  for (int64_t bit_len : bit_lengths) {
    benchmark::RegisterBenchmark("BM_PlainCommit", BM_PlainCommit)
        ->Arg(bit_len);
    benchmark::RegisterBenchmark("BM_PlainVerify", BM_PlainVerify)
        ->Arg(bit_len);
  }
}

void register_batch_benchmarks() {
  constexpr int64_t batch_sizes[] = {1000, 100000, 1000000};
  for (int64_t batch_size : batch_sizes) {
    benchmark::RegisterBenchmark("BM_PlainCommitBatch", BM_PlainCommitBatch)
        ->Arg(batch_size)
        ->UseManualTime();
  }
}

} // namespace

int main(int argc, char **argv) {
  register_scalar_benchmarks();
  register_batch_benchmarks();
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
