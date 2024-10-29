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

#include "examples/upsi/ecdhpsi/ecdh_psi.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"

inline std::vector<size_t> GetIntersectionIdx(
    const std::vector<std::string>& x, const std::vector<std::string>& y) {
  std::set<std::string> set(x.begin(), x.end());
  std::vector<size_t> ret;
  for (size_t i = 0; i < y.size(); ++i) {
    if (set.count(y[i]) != 0) {
      ret.push_back(i);
    }
  }
  return ret;
}

void EcdhPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<std::string>& x, size_t size_y) {
  EcdhPsi alice;
  std::vector<yc::EcPoint> x_points(x.size());
  alice.MaskStrings(absl::MakeSpan(x), absl::MakeSpan(x_points));

  // Send H(id)^a
  uint64_t max_point_length =
      alice.ec_->GetSerializeLength();  
  uint64_t total_length_x = max_point_length * x.size();

  std::vector<uint8_t> xbuffer(total_length_x);
  alice.PointstoBuffer(absl::MakeSpan(x_points), absl::MakeSpan(xbuffer));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(xbuffer.data(), total_length_x * sizeof(uint8_t)),
      "Send H(id)^a");

  // Receive H(id)^b
  uint64_t total_length_y = max_point_length * size_y;
  std::vector<uint8_t> ybuffer(total_length_y);
  std::vector<yc::EcPoint> y_points(size_y);
  auto bufypoints = ctx->Recv(ctx->PrevRank(), "Receive H(id)^b");
  YACL_ENFORCE(bufypoints.size() == int64_t(total_length_y * sizeof(uint8_t)));
  std::memcpy(ybuffer.data(), bufypoints.data(), bufypoints.size());
  alice.BuffertoPoints(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));

  std::vector<yc::EcPoint> y_mask(size_y);
  // y_str = y_points ^ {alice_sk}
  alice.MaskEcPoints(absl::MakeSpan(y_points), absl::MakeSpan(y_mask));
  std::vector<uint8_t> maskbuffer(total_length_y);
  alice.PointstoBuffer(absl::MakeSpan(y_mask), absl::MakeSpan(maskbuffer));

  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(maskbuffer.data(),
                                         maskbuffer.size() * sizeof(uint8_t)),
                 "Send y_mask");
}

std::vector<size_t> EcdhPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<std::string>& y, size_t size_x) {
  EcdhPsi bob;
  std::vector<yc::EcPoint> y_points(y.size());
  // y_points = H(y) ^ {bob_sk}
  bob.MaskStrings(absl::MakeSpan(y), absl::MakeSpan(y_points));
  uint64_t max_point_length =
      bob.ec_->GetSerializeLength();  // 获取点的最大序列化长度

  // Receive H(id)^a
  uint64_t total_length_x = size_x * max_point_length;
  std::vector<uint8_t> buffer(total_length_x);
  std::vector<yc::EcPoint> x_points(size_x);
  auto bufxpoints = ctx->Recv(ctx->PrevRank(), "Receive H(id)^a");
  YACL_ENFORCE(bufxpoints.size() == int64_t(total_length_x * sizeof(uint8_t)));
  std::memcpy(buffer.data(), bufxpoints.data(), bufxpoints.size());
  bob.BuffertoPoints(absl::MakeSpan(x_points), absl::MakeSpan(buffer));

  // Send H(id)^b
  uint64_t total_length_y = y.size() * max_point_length;
  std::vector<uint8_t> ybuffer(total_length_y);
  bob.PointstoBuffer(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(ybuffer.data(), total_length_y * sizeof(uint8_t)),
      "Send H(id)^b");

  std::vector<std::string> x_str(size_x);
  // x_str = x_points ^ {bob_sk}
  bob.MaskEcPointsD(absl::MakeSpan(x_points), absl::MakeSpan(x_str));

  std::vector<std::string> y_str(y.size());

  auto bufy_str = ctx->Recv(ctx->PrevRank(), "Receive y_str");
  YACL_ENFORCE(bufy_str.size() == int64_t(total_length_y * sizeof(uint8_t)));
  std::vector<uint8_t> maskbuffer(total_length_y);
  std::memcpy(maskbuffer.data(), bufy_str.data(), bufy_str.size());
  yacl::parallel_for(0, y.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * max_point_length;
      y_str[idx] =
          std::string(reinterpret_cast<const char*>(maskbuffer.data() + offset),
                      max_point_length);
    }
  });
  auto z = GetIntersectionIdx(x_str, y_str);
  return z;
}

void EcdhPsi::MaskStrings(absl::Span<std::string> in,
                          absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[idx]);
      ec_->MulInplace(&out[idx], sk_);
    }
  });
}

void EcdhPsi::MaskEcPoints(absl::Span<yc::EcPoint> in,
                           absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->Mul(in[idx], sk_);
    }
  });
}

void EcdhPsi::MaskEcPointsD(absl::Span<yc::EcPoint> in,
                            absl::Span<std::string> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->SerializePoint(ec_->Mul(in[idx], sk_));
    }
  });
}

void EcdhPsi::PointstoBuffer(absl::Span<yc::EcPoint> in,
                             absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      ec_->SerializePoint(in[idx], buffer.data() + offset, 32);
    }
  });
}

void EcdhPsi::BuffertoPoints(absl::Span<yc::EcPoint> in,
                             absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      in[idx] =
          ec_->DeserializePoint(absl::MakeSpan(buffer.data() + offset, 32));
    }
  });
}
