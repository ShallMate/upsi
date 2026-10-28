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

#pragma once

#include <memory>
#include <vector>

#include "runtime/types.h"
#include "runtime/field.h"
#include "runtime/link.h"

/* submodules */

/* security parameter declaration */

namespace examples::psu {

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x);

std::vector<uint64_t> Interpolate(const std::vector<uint64_t>& xs,
                                  const std::vector<uint64_t>& ys);

// Scalable Private Set Union from Symmetric-Key Techniques
// https://eprint.iacr.org/2019/776.pdf (Figure 10)

void KrtwPsuSend(const std::shared_ptr<upsi_runtime::link::Context>& ctx,
                 const std::vector<uint128_t>& elem_hashes);

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<upsi_runtime::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes);

}  // namespace examples::psu
