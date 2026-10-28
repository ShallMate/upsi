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

#include "runtime/curve.h"
#include "runtime/link.h"

namespace yc = upsi_runtime::crypto;

class EcdhReceiver {
 public:
  EcdhReceiver() {
    ec_ = std::make_shared<yc::EcGroup>();

    // Generate random key
    sk_ = yc::RandomScalar();
    skinv_ = sk_.inverse();
  }
  // Mask input strings with secret key, and outputs the EcPoint results
  void MaskStrings(upsi_runtime::Span<std::string> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskInputs(upsi_runtime::Span<uint128_t> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskEcPoints(upsi_runtime::Span<yc::EcPoint> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskEcPointsInv(upsi_runtime::Span<yc::EcPoint> in, upsi_runtime::Span<yc::EcPoint> out);
  void MaskEcPointsD(upsi_runtime::Span<yc::EcPoint> in, upsi_runtime::Span<std::string> out);
  void PointstoBuffer(upsi_runtime::Span<yc::EcPoint> in,
                      upsi_runtime::Span<std::uint8_t> buffer);
  void BuffertoPoints(upsi_runtime::Span<yc::EcPoint> in,
                      upsi_runtime::Span<std::uint8_t> buffer);
  std::vector<uint128_t> EcdhPsiRecv(
      const std::shared_ptr<upsi_runtime::link::Context>& ctx,
      std::vector<uint128_t>& y);

 private:
  yc::Scalar sk_;  // secret key
  yc::Scalar skinv_;

 public:
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};
