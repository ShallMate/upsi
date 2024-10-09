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

#include "examples/upsi/ecdhpsi/receiver.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "examples/upsi/ecdhpsi/sender.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"

std::vector<uint128_t> GetIntersection(std::vector<uint32_t> z,
                                       std::vector<uint128_t> y,
                                       uint32_t z_size) {
  std::vector<uint128_t> intersection(z_size);
  yacl::parallel_for(0, z_size, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      intersection[idx] = y[z[idx]];
    }
  });
  return intersection;
}

std::vector<uint32_t> ConvertToUint32Vector(const std::vector<uint8_t>& input,
                                            uint32_t z_size) {
  std::vector<uint32_t> z(z_size);
  yacl::parallel_for(0, z_size, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto index = idx * 4;
      z[idx] = static_cast<uint32_t>(input[index]) |
               (static_cast<uint32_t>(input[index + 1]) << 8) |
               (static_cast<uint32_t>(input[index + 2]) << 16) |
               (static_cast<uint32_t>(input[index + 3]) << 24);
    }
  });
  return z;
}

void EcdhReceiver::MaskStrings(absl::Span<std::string> in,
                               absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[idx]);
      ec_->MulInplace(&out[idx], sk_);
    }
  });
}

void EcdhReceiver::MaskInputs(absl::Span<uint128_t> in,
                              absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous,
                                  uint128_to_string(in[idx]));
      ec_->MulInplace(&out[idx], sk_);
    }
  });
}

void EcdhReceiver::MaskEcPoints(absl::Span<yc::EcPoint> in,
                                absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->Mul(in[idx], sk_);
    }
  });
}

void EcdhReceiver::MaskEcPointsInv(absl::Span<yc::EcPoint> in,
                                   absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->Mul(in[idx], skinv_);
    }
  });
}

void EcdhReceiver::MaskEcPointsD(absl::Span<yc::EcPoint> in,
                                 absl::Span<std::string> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->SerializePoint(ec_->Mul(in[idx], sk_));
    }
  });
}

void EcdhReceiver::PointstoBuffer(absl::Span<yc::EcPoint> in,
                                  absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      ec_->SerializePoint(in[idx], buffer.data() + offset, 32);
    }
  });
}

void EcdhReceiver::BuffertoPoints(absl::Span<yc::EcPoint> in,
                                  absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      in[idx] =
          ec_->DeserializePoint(absl::MakeSpan(buffer.data() + offset, 32));
    }
  });
}

std::vector<uint128_t> EcdhReceiver::EcdhPsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& y) {
  std::vector<yc::EcPoint> y_points(y.size());

  // y_points = H(y) ^ {bob_sk}
  MaskInputs(absl::MakeSpan(y), absl::MakeSpan(y_points));

  // Send H(id)^b
  uint64_t total_length_y = y.size() * 32;
  std::vector<uint8_t> ybuffer(total_length_y);
  PointstoBuffer(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(ybuffer.data(), total_length_y * sizeof(uint8_t)),
      "Send H(id)^b");

  // Receive H(id)^ab
  auto bufypoints = ctx->Recv(ctx->PrevRank(), "Receive y_mask");
  YACL_ENFORCE(bufypoints.size() == int64_t(total_length_y * sizeof(uint8_t)));
  std::memcpy(ybuffer.data(), bufypoints.data(), bufypoints.size());
  BuffertoPoints(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));

  std::vector<yc::EcPoint> maskpoints(y.size());
  MaskEcPointsInv(absl::MakeSpan(y_points), absl::MakeSpan(maskpoints));
  PointstoBuffer(absl::MakeSpan(maskpoints), absl::MakeSpan(ybuffer));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(ybuffer.data(), total_length_y * sizeof(uint8_t)),
      "Send H(id)^a");

  yacl::Buffer size_data = ctx->Recv(ctx->PrevRank(), "intersection size");

  uint32_t z_size = *reinterpret_cast<uint32_t*>(size_data.data());
  auto index_data = ctx->Recv(ctx->PrevRank(), "intersection index");
  std::vector<uint8_t> index_buffer(z_size * 4);
  std::memcpy(index_buffer.data(), index_data.data(), index_data.size());
  std::vector<uint32_t> z = ConvertToUint32Vector(index_buffer, z_size);
  auto psi_result = GetIntersection(z, y, z_size);

  return psi_result;
}