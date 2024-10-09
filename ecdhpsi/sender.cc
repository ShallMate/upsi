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

#include "examples/upsi/ecdhpsi/sender.h"

#include <cstdint>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"

inline std::vector<uint32_t> GetIntersectionIdx(
    const std::set<std::string>& x, const std::vector<std::string>& y) {
  // std::set<std::string> set(x.begin(), x.end());
  std::vector<uint32_t> ret;
  for (uint32_t i = 0; i < y.size(); ++i) {
    if (x.count(y[i]) != 0) {
      ret.push_back(i);
    }
  }
  return ret;
}

std::vector<uint8_t> ConvertToUint8Vector(const std::vector<uint32_t>& input) {
  std::vector<uint8_t> output(input.size() * 4);
  yacl::parallel_for(0, input.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto index = idx * 4;
      output[index] = static_cast<uint8_t>(input[idx] & 0xFF);
      output[index + 1] = static_cast<uint8_t>((input[idx] >> 8) & 0xFF);
      output[index + 2] = static_cast<uint8_t>((input[idx] >> 16) & 0xFF);
      output[index + 3] = static_cast<uint8_t>((input[idx] >> 24) & 0xFF);
    }
  });
  return output;
}

void EcdhSender::MaskStrings(absl::Span<std::string> in,
                             absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous, in[idx]);
      ec_->MulInplace(&out[idx], sk_);
    }
  });
}

void EcdhSender::MaskInputs(absl::Span<uint128_t> in,
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

void EcdhSender::UpdatePRFs(absl::Span<uint128_t> in) {
  std::vector<std::string> out(in.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto point = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous,
                                    uint128_to_string(in[idx]));
      ec_->MulInplace(&point, sk_);
      out[idx] = ec_->SerializePoint(point);
    }
  });
  prfs_.insert(out.begin(), out.end());
}

void EcdhSender::DeletePRFs(absl::Span<uint128_t> in) {
  std::vector<std::string> out(in.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto point = ec_->HashToCurve(yc::HashToCurveStrategy::Autonomous,
                                    uint128_to_string(in[idx]));
      ec_->MulInplace(&point, sk_);
      out[idx] = ec_->SerializePoint(point);
    }
  });
  std::set<std::string> result;
  std::set_difference(prfs_.begin(), prfs_.end(), out.begin(), out.end(),
                      std::inserter(result, result.end()));
  prfs_.swap(result);
}

void EcdhSender::MaskEcPoints(absl::Span<yc::EcPoint> in,
                              absl::Span<yc::EcPoint> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->Mul(in[idx], sk_);
    }
  });
}

void EcdhSender::MaskEcPointsD(absl::Span<yc::EcPoint> in,
                               absl::Span<std::string> out) {
  YACL_ENFORCE(in.size() == out.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      out[idx] = ec_->SerializePoint(ec_->Mul(in[idx], sk_));
    }
  });
}

void EcdhSender::PointstoBuffer(absl::Span<yc::EcPoint> in,
                                absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      ec_->SerializePoint(in[idx], buffer.data() + offset, 32);
    }
  });
}

void EcdhSender::BuffertoPoints(absl::Span<yc::EcPoint> in,
                                absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      in[idx] =
          ec_->DeserializePoint(absl::MakeSpan(buffer.data() + offset, 32));
    }
  });
}

void EcdhSender::BuffertoStrings(absl::Span<std::uint8_t> in,
                                 absl::Span<std::string> out) {
  yacl::parallel_for(0, out.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      out[idx] =
          std::string(reinterpret_cast<const char*>(in.data() + offset), 32);
    }
  });
}

void EcdhSender::EcdhPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                             size_t size_receiver) {
  // Receive H(id)^b
  uint64_t total_length_receiver = 32 * size_receiver;
  std::vector<uint8_t> ybuffer(total_length_receiver);
  std::vector<yc::EcPoint> y_points(size_receiver);
  auto bufypoints = ctx->Recv(ctx->PrevRank(), "Receive H(id)^b");
  YACL_ENFORCE(bufypoints.size() ==
               int64_t(total_length_receiver * sizeof(uint8_t)));
  std::memcpy(ybuffer.data(), bufypoints.data(), bufypoints.size());
  BuffertoPoints(absl::MakeSpan(y_points), absl::MakeSpan(ybuffer));
  std::vector<yc::EcPoint> y_mask(size_receiver);
  // y_str = y_points ^ {alice_sk}
  MaskEcPoints(absl::MakeSpan(y_points), absl::MakeSpan(y_mask));
  std::vector<uint8_t> maskbuffer(total_length_receiver);
  PointstoBuffer(absl::MakeSpan(y_mask), absl::MakeSpan(maskbuffer));
  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(maskbuffer.data(),
                                         maskbuffer.size() * sizeof(uint8_t)),
                 "Send y_mask");

  std::vector<std::string> y_mask_string(size_receiver);
  bufypoints = ctx->Recv(ctx->PrevRank(), "Receive H(id)^a");
  YACL_ENFORCE(bufypoints.size() ==
               int64_t(total_length_receiver * sizeof(uint8_t)));
  std::memcpy(ybuffer.data(), bufypoints.data(), bufypoints.size());
  BuffertoStrings(absl::MakeSpan(ybuffer), absl::MakeSpan(y_mask_string));
  std::vector<uint32_t> z = GetIntersectionIdx(prfs_, y_mask_string);
  uint32_t z_size = z.size();
  std::vector<uint8_t> size_data(
      reinterpret_cast<uint8_t*>(&z_size),
      reinterpret_cast<uint8_t*>(&z_size) + sizeof(z_size));
  ctx->SendAsync(ctx->NextRank(), size_data, "intersection size");
  std::vector<uint8_t> z_data = ConvertToUint8Vector(z);

  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(z_data.data(), z_data.size() * sizeof(uint8_t)),
      "intersection index");
}

uint32_t EcdhSender::GetPRFSize() { return prfs_.size(); }