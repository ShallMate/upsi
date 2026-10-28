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

#pragma once

#include <cstdint>
#include <memory>
#include <vector>

#include "runtime/curve.h"
#include "runtime/link.h"

inline std::string uint128_to_string(uint128_t value) {
  if (value == 0) {
    return "0";
  }
  std::array<char, 40> buffer;
  int pos = 39;
  buffer[pos] = '\0';
  while (value > 0) {
    buffer[--pos] = '0' + static_cast<char>(value % 10);
    value /= 10;
  }
  return std::string(&buffer[pos]);
}

namespace yc = upsi_runtime::crypto;

class EcdhSender {
 public:
  EcdhSender() {
    ec_ = std::make_shared<yc::EcGroup>();

    // Generate random key
    sk_ = yc::RandomScalar();
  }

  // Mask input strings with secret key, and outputs the EcPoint results
  void MaskStrings(upsi_runtime::Span<std::string> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskInputs(upsi_runtime::Span<uint128_t> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskEcPoints(upsi_runtime::Span<yc::EcPoint> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskEcPointsD(upsi_runtime::Span<yc::EcPoint> in, upsi_runtime::Span<std::string> out);
  void PointstoBuffer(upsi_runtime::Span<yc::EcPoint> in,
                      upsi_runtime::Span<std::uint8_t> buffer);
  void BuffertoPoints(upsi_runtime::Span<yc::EcPoint> in,
                      upsi_runtime::Span<std::uint8_t> buffer);
  void BuffertoStrings(upsi_runtime::Span<std::uint8_t> in,
                       upsi_runtime::Span<std::string> out);
  void UpdatePRFs(upsi_runtime::Span<uint128_t> in);
  void DeletePRFs(upsi_runtime::Span<uint128_t> in);
  void EcdhPsiSend(const std::shared_ptr<upsi_runtime::link::Context>& ctx,
                   size_t size_receiver);
  uint32_t GetPRFSize();

 private:
  yc::Scalar sk_;  // secret key
  std::set<std::string> prfs_;

 public:
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};
