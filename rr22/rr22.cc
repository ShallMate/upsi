
// Copyright 2024 Guowei LING.
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

#include "rr22/rr22.h"

#include <iostream>
#include <vector>

#include "runtime/vole.h"
#include "runtime/types.h"

namespace rr22 {

std::vector<uint128_t> GetIntersection(std::vector<int32_t> z,
                                       std::vector<uint128_t> y,
                                       uint32_t z_size) {
  std::vector<uint128_t> intersection(z_size);
  upsi_runtime::parallel_for(0, z_size, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      intersection[idx] = y[z[idx]];
    }
  });
  return intersection;
}

inline std::vector<int32_t> GetIntersectionIdx(
    const std::vector<uint128_t>& x, const std::vector<uint128_t>& y) {
  std::set<uint128_t> set(x.begin(), x.end());
  std::vector<int32_t> ret(y.size(), -1);  // 初始化为 -1

  upsi_runtime::parallel_for(0, y.size(), [&](size_t start, size_t end) {
    for (size_t i = start; i < end; ++i) {
      if (set.count(y[i]) != 0) {
        ret[i] = i;
      }
    }
  });

  // 清除所有值为 -1 的元素
  ret.erase(std::remove(ret.begin(), ret.end(), -1), ret.end());

  return ret;
}

std::vector<uint128_t> RR22PsiRecv(
    const std::shared_ptr<upsi_runtime::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos) {
  uint128_t okvssize = baxos.size();

  // VOLE
  ctx->SendAsync(ctx->NextRank(), upsi_runtime::SerializeUint128(okvssize),
                 "baxos.size");
  // VOLE
  std::vector<uint128_t> a(okvssize);
  std::vector<uint128_t> c(okvssize);
  auto volereceiver = std::async([&] {
    upsi_runtime::crypto::VoleReceive(*ctx, a, c);
  });

  // Encode
  std::vector<uint128_t> p(okvssize);
  baxos.Solve(upsi_runtime::MakeSpan(elem_hashes), upsi_runtime::MakeSpan(elem_hashes),
              upsi_runtime::MakeSpan(p), nullptr, upsi_runtime::parallel_threads.load());
  volereceiver.get();

  std::vector<uint128_t> aprime(okvssize);

  upsi_runtime::parallel_for(0, aprime.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      aprime[idx] = a[idx] ^ p[idx];
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      upsi_runtime::ByteContainerView(aprime.data(), aprime.size() * sizeof(uint128_t)),
      "Send A' = P+A");
  std::vector<uint128_t> receivermasks(elem_hashes.size());
  baxos.Decode(upsi_runtime::MakeSpan(elem_hashes), upsi_runtime::MakeSpan(receivermasks),
               upsi_runtime::MakeSpan(c), upsi_runtime::parallel_threads.load());
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive masks of sender");
  UPSI_ENFORCE(buf.size() == int64_t(elem_hashes.size() * sizeof(uint128_t)));
  std::memcpy(sendermasks.data(), buf.data(), buf.size());

  auto z = GetIntersectionIdx(sendermasks, receivermasks);
  uint32_t z_size = z.size();
  std::vector<uint8_t> size_data(
      reinterpret_cast<uint8_t*>(&z_size),
      reinterpret_cast<uint8_t*>(&z_size) + sizeof(z_size));
  ctx->SendAsync(ctx->NextRank(), size_data, "intersection size");
  auto psi_result = GetIntersection(z, elem_hashes, z.size());

  ctx->SendAsync(ctx->NextRank(),
                 upsi_runtime::ByteContainerView(psi_result.data(),
                                         psi_result.size() * sizeof(uint128_t)),
                 "Send intersection");
  return psi_result;
}

std::vector<uint128_t> RR22PsiSend(
    const std::shared_ptr<upsi_runtime::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos) {
  size_t okvssize =
      DeserializeUint128(ctx->Recv(ctx->PrevRank(), "baxos.size"));
  std::vector<uint128_t> b(okvssize);
  uint128_t delta = 0;
  auto volesender = std::async([&] {
    delta = upsi_runtime::crypto::VoleSend(*ctx, b);
  });
  volesender.get();
  std::vector<uint128_t> aprime(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive A' = P+A");
  UPSI_ENFORCE(buf.size() == int64_t(okvssize * sizeof(uint128_t)));
  std::memcpy(aprime.data(), buf.data(), buf.size());
  std::vector<uint128_t> k(okvssize);
  upsi_runtime::parallel_for(0, okvssize, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      k[idx] = b[idx] ^ upsi_runtime::crypto::GfMul128(delta, aprime[idx]);
    }
  });
  std::vector<uint128_t> sendermasks(elem_hashes.size());
  baxos.Decode(upsi_runtime::MakeSpan(elem_hashes), upsi_runtime::MakeSpan(sendermasks),
               upsi_runtime::MakeSpan(k), upsi_runtime::parallel_threads.load());
  upsi_runtime::parallel_for(0, elem_hashes.size(), [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      sendermasks[idx] =
          sendermasks[idx] ^ upsi_runtime::crypto::GfMul128(delta, elem_hashes[idx]);
    }
  });
  ctx->SendAsync(
      ctx->NextRank(),
      upsi_runtime::ByteContainerView(sendermasks.data(),
                              sendermasks.size() * sizeof(uint128_t)),
      "Send masks of sender");
  upsi_runtime::Buffer size_data = ctx->Recv(ctx->PrevRank(), "intersection size");

  uint32_t z_size = *reinterpret_cast<uint32_t*>(size_data.data());
  std::vector<uint128_t> intersection(z_size);
  auto bufintersection = ctx->Recv(ctx->PrevRank(), "Receive intersection");
  UPSI_ENFORCE(bufintersection.size() == int64_t(z_size * sizeof(uint128_t)));
  std::memcpy(intersection.data(), bufintersection.data(),
              bufintersection.size());
  return intersection;
}

}  // namespace rr22