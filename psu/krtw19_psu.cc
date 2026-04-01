// Copyright 2024 Guowei Ling
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "examples/upsi/psu/krtw19_psu.h"

#include <algorithm>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <vector>

#include "yacl/utils/serialize.h"

namespace examples::psu {

namespace {

// reference: https://eprint.iacr.org/2019/1234.pdf (Figure 2)
constexpr float kZeta{0.06F};
constexpr size_t kBinSize{64UL};  // m+1
constexpr uint128_t kBot{0};
constexpr size_t kNumBinsPerBatch{16UL};
constexpr size_t kBatchSize{kNumBinsPerBatch * kBinSize};
constexpr size_t kNumInkpOT{512UL};

auto inline HashToSizeT = [](const uint128_t& x) {
  auto hash = yacl::crypto::Blake3_128({&x, sizeof(x)});
  size_t ret;
  std::memcpy(&ret, &hash, sizeof(ret));
  return ret;
};

auto HashInputs(const std::vector<uint128_t>& elem_hashes, size_t count) {
  size_t num_bins = std::ceil(count * kZeta);
  std::vector<std::vector<uint128_t>> hashing(num_bins);
  for (const auto& elem : elem_hashes) {
    auto hash = HashToSizeT(elem);
    hashing[hash % num_bins].emplace_back(elem);
  }
  return hashing;
}

}  // namespace

uint64_t Evaluate(const uint64_t* coeffs, size_t size, uint64_t x) {
  YACL_ENFORCE(size > 0);
  uint64_t y = coeffs[size - 1];
  for (size_t idx = size - 1; idx > 0; --idx) {
    y = yacl::GfMul64(y, x) ^ coeffs[idx - 1];
  }
  return y;
}

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x) {
  return Evaluate(coeffs.data(), coeffs.size(), x);
}

std::vector<uint64_t> Interpolate(const std::vector<uint64_t>& xs,
                                  const std::vector<uint64_t>& ys) {
  YACL_ENFORCE(xs.size() == ys.size());
  auto size = xs.size();
  auto poly = std::vector<uint64_t>(size + 1, 0);

  // Compute poly = (x - x0)(x - x1) ... (x - xn)
  poly[0] = 1;
  for (size_t j = 0; j < size; ++j) {
    uint64_t sum = 0;
    for (size_t k = 0; k <= j + 1; ++k) {
      sum = std::exchange(poly[k], yacl::GfMul64(poly[k], xs[j]) ^ sum);
    }
  }

  auto coeffs = std::vector<uint64_t>(size, 0);  // result

  for (size_t i = 0; i < size; ++i) {
    // subpoly = poly / (x - xi)
    auto subpoly = std::vector<uint64_t>(size, 0);
    uint64_t xi = xs[i];
    subpoly[size - 1] = 1;
    for (int32_t k = size - 2; k >= 0; --k) {
      subpoly[k] = poly[k + 1] ^ yacl::GfMul64(subpoly[k + 1], xi);
    }

    auto prod = yacl::GfMul64(ys[i], yacl::GfInv64(Evaluate(subpoly, xi)));
    // update coeff
    for (size_t k = 0; k < size; ++k) {
      coeffs[k] = coeffs[k] ^ yacl::GfMul64(subpoly[k], prod);
    }
  }

  return coeffs;
}

void KrtwPsuSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 const std::vector<uint128_t>& elem_hashes) {
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(elem_hashes.size()),
                 "Send set size");
  size_t peer_count =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return;
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  yacl::crypto::KkrtOtExtReceiver receiver;
  const size_t num_ot = hashing.size() * kBinSize;
  auto ss_sender = yacl::crypto::SoftspokenOtExtSender();
  auto store = ss_sender.GenRot(ctx, kNumInkpOT);

  receiver.Init(ctx, store, num_ot);
  receiver.SetBatchSize(kBatchSize);

  std::vector<uint128_t> elems(num_ot);
  size_t batch_ot_start = 0;
  size_t oprf_idx = 0;
  const size_t num_bin_batches =
      (hashing.size() + kNumBinsPerBatch - 1) / kNumBinsPerBatch;
  for (size_t batch_idx = 0; batch_idx != num_bin_batches; ++batch_idx) {
    const size_t batch_bin_start = batch_idx * kNumBinsPerBatch;
    const size_t num_bins_this_batch =
        std::min(kNumBinsPerBatch, hashing.size() - batch_bin_start);
    const size_t num_this_batch = num_bins_this_batch * kBinSize;
    std::vector<uint64_t> evals(num_this_batch);

    for (size_t local_bin_idx = 0; local_bin_idx != num_bins_this_batch;
         ++local_bin_idx) {
      auto& bin = hashing[batch_bin_start + local_bin_idx];
      bin.resize(kBinSize);
      std::sort(bin.begin(), bin.end());
      for (size_t elem_idx = 0; elem_idx != kBinSize; ++elem_idx, ++oprf_idx) {
        uint64_t result;
        const auto& elem = bin[elem_idx];
        receiver.Encode(oprf_idx, HashToSizeT(elem),
                        {reinterpret_cast<uint8_t*>(&result), sizeof(result)});
        evals[local_bin_idx * kBinSize + elem_idx] = result;
        elems[oprf_idx] = elem;
      }
    }

    receiver.SendCorrection(ctx, num_this_batch);

    std::vector<uint64_t> coeffs(num_this_batch * kBinSize);
    auto coeff_buf = ctx->Recv(ctx->PrevRank(), "Receive coefficients batch");
    YACL_ENFORCE(coeff_buf.size() ==
                 int64_t(coeffs.size() * sizeof(uint64_t)));
    std::memcpy(coeffs.data(), coeff_buf.data(),
                coeffs.size() * sizeof(uint64_t));

    std::vector<uint64_t> eval_payload(num_this_batch);
    for (size_t local_ot_idx = 0; local_ot_idx != num_this_batch;
         ++local_ot_idx) {
      const auto global_ot_idx = batch_ot_start + local_ot_idx;
      const auto* coeff_ptr = coeffs.data() + local_ot_idx * kBinSize;
      eval_payload[local_ot_idx] =
          Evaluate(coeff_ptr, kBinSize, HashToSizeT(elems[global_ot_idx])) ^
          evals[local_ot_idx];
    }
    ctx->SendAsync(ctx->NextRank(),
                   yacl::ByteContainerView(eval_payload.data(),
                                           eval_payload.size() *
                                               sizeof(uint64_t)),
                   "Send evaluation batch");
    batch_ot_start += num_this_batch;
  }

  // Step 4. Sends new elements through OT
  auto keys = ss_sender.GenRot(ctx, num_ot);
  std::vector<uint128_t> ciphers(num_ot);
  for (size_t i = 0; i != num_ot; ++i) {
    ciphers[i] = elems[i] ^ keys.GetBlock(i, 0);
  }
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(ciphers.data(),
                                         ciphers.size() * sizeof(uint128_t)),
                 "Send ciphertexts");
}

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  size_t peer_count =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "Receive set size"));
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(elem_hashes.size()),
                 "Send set size");
  auto count = std::max(elem_hashes.size(), peer_count);
  if (count == 0) {
    return {};
  }
  // Step 1. Hashes inputs
  auto hashing = HashInputs(elem_hashes, count);

  // Step 2. Prepares OPRF
  const size_t num_ot = hashing.size() * kBinSize;
  auto ss_receiver = yacl::crypto::SoftspokenOtExtReceiver();
  auto store = ss_receiver.GenRot(ctx, kNumInkpOT);

  yacl::crypto::KkrtOtExtSender sender;
  sender.Init(ctx, store, num_ot);
  sender.SetBatchSize(kBatchSize);
  auto oprf = sender.GetOprf();

  yacl::dynamic_bitset<uint128_t> ot_choice(num_ot);
  size_t oprf_idx = 0;
  size_t batch_ot_start = 0;
  const size_t num_bin_batches =
      (hashing.size() + kNumBinsPerBatch - 1) / kNumBinsPerBatch;
  // Step 3. For each bin batch, invokes PSU(1, m+1)
  for (size_t batch_idx = 0; batch_idx != num_bin_batches; ++batch_idx) {
    const size_t batch_bin_start = batch_idx * kNumBinsPerBatch;
    const size_t num_bins_this_batch =
        std::min(kNumBinsPerBatch, hashing.size() - batch_bin_start);
    const size_t num_this_batch = num_bins_this_batch * kBinSize;
    sender.RecvCorrection(ctx, num_this_batch);

    std::vector<uint64_t> coeffs_payload(num_this_batch * kBinSize);
    std::vector<uint64_t> seeds(num_this_batch);

    for (size_t local_bin_idx = 0; local_bin_idx != num_bins_this_batch;
         ++local_bin_idx) {
      const auto& bin = hashing[batch_bin_start + local_bin_idx];
      const auto bin_size = bin.size();
      for (size_t elem_idx = 0; elem_idx != kBinSize; ++elem_idx, ++oprf_idx) {
        auto seed = yacl::crypto::FastRandU64();
        const size_t local_ot_idx = local_bin_idx * kBinSize + elem_idx;
        seeds[local_ot_idx] = seed;
        std::vector<uint64_t> xs(kBinSize);
        std::vector<uint64_t> ys(kBinSize);
        for (size_t i = 0; i != kBinSize; ++i) {
          if (i < bin_size) {
            xs[i] = HashToSizeT(bin[i]);
          } else if (i > bin_size) {
            xs[i] = yacl::crypto::FastRandU64();
          } else {
            xs[i] = kBot;
          }
          oprf->Eval(oprf_idx, xs[i], reinterpret_cast<uint8_t*>(&ys[i]),
                     sizeof(ys[i]));
          ys[i] ^= seed;
        }
        auto coeffs = Interpolate(xs, ys);
        std::memcpy(coeffs_payload.data() + local_ot_idx * kBinSize,
                    coeffs.data(), kBinSize * sizeof(uint64_t));
      }
    }

    ctx->SendAsync(ctx->NextRank(),
                   yacl::ByteContainerView(coeffs_payload.data(),
                                           coeffs_payload.size() *
                                               sizeof(uint64_t)),
                   "Send coefficients batch");

    std::vector<uint64_t> eval_payload(num_this_batch);
    auto eval_buf = ctx->Recv(ctx->PrevRank(), "Receive evaluation batch");
    YACL_ENFORCE(eval_buf.size() ==
                 int64_t(eval_payload.size() * sizeof(uint64_t)));
    std::memcpy(eval_payload.data(), eval_buf.data(),
                eval_payload.size() * sizeof(uint64_t));

    for (size_t local_ot_idx = 0; local_ot_idx != num_this_batch;
         ++local_ot_idx) {
      ot_choice[batch_ot_start + local_ot_idx] =
          (eval_payload[local_ot_idx] == seeds[local_ot_idx]);
    }
    batch_ot_start += num_this_batch;
  }

  // Step 4. Receives new elements through OT
  auto keys = ss_receiver.GenRot(ctx, ot_choice);
  std::vector<uint128_t> ciphers(num_ot);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive ciphertexts");
  YACL_ENFORCE(buf.size() == int64_t(num_ot * sizeof(uint128_t)));
  std::memcpy(ciphers.data(), buf.data(), buf.size());

  std::set<uint128_t> set_union(elem_hashes.begin(), elem_hashes.end());

  for (size_t i = 0; i != num_ot; ++i) {
    if (!ot_choice[i]) {
      auto new_elem = ciphers[i] ^ keys.GetBlock(i);
      if (new_elem != kBot) {
        set_union.emplace(new_elem);
      }
    }
  }
  return std::vector(set_union.begin(), set_union.end());
}

}  // namespace examples::psu
