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

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"

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

namespace yc = yacl::crypto;

class EcdhSender {
 public:
  EcdhSender() {
    // Use FourQ curve
    ec_ = yc::EcGroupFactory::Instance().Create(/* curve name */ "FourQ");

    // Generate random key
    yc::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
  }

  // Mask input strings with secret key, and outputs the EcPoint results
  void MaskStrings(absl::Span<std::string> in, absl::Span<yc::EcPoint> out);
  void MaskInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> out);
  void MaskEcPoints(absl::Span<yc::EcPoint> in, absl::Span<yc::EcPoint> out);
  void MaskEcPointsD(absl::Span<yc::EcPoint> in, absl::Span<std::string> out);
  void PointstoBuffer(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);
  void BuffertoPoints(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);
  void BuffertoStrings(absl::Span<std::uint8_t> in,
                       absl::Span<std::string> out);
  void UpdatePRFs(absl::Span<uint128_t> in);
  void DeletePRFs(absl::Span<uint128_t> in);
  void EcdhPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                   size_t size_receiver);
  uint32_t GetPRFSize();

 private:
  yc::MPInt sk_;  // secret key
  std::set<std::string> prfs_;

 public:
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};
