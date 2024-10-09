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

#include <memory>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"

namespace yc = yacl::crypto;

class EcdhReceiver {
 public:
  EcdhReceiver() {
    // Use FourQ curve
    ec_ = yc::EcGroupFactory::Instance().Create(/* curve name */ "FourQ");

    // Generate random key
    yc::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
    skinv_.Set(sk_);
    skinv_ = skinv_.InvertMod(ec_->GetOrder());
  }
  // Mask input strings with secret key, and outputs the EcPoint results
  void MaskStrings(absl::Span<std::string> in, absl::Span<yc::EcPoint> out);
  void MaskInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> out);
  void MaskEcPoints(absl::Span<yc::EcPoint> in, absl::Span<yc::EcPoint> out);
  void MaskEcPointsInv(absl::Span<yc::EcPoint> in, absl::Span<yc::EcPoint> out);
  void MaskEcPointsD(absl::Span<yc::EcPoint> in, absl::Span<std::string> out);
  void PointstoBuffer(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);
  void BuffertoPoints(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);
  std::vector<uint128_t> EcdhPsiRecv(
      const std::shared_ptr<yacl::link::Context>& ctx,
      std::vector<uint128_t>& y);

 private:
  yc::MPInt sk_;  // secret key
  yc::MPInt skinv_;

 public:
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};
