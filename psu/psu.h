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
#include "yacl/link/context.h"
#include "yacl/secparam.h"

YACL_MODULE_DECLARE("psu", SecParam::C::k128, SecParam::S::k40);

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x);

std::vector<uint64_t> Interpolate(const std::vector<uint64_t>& xs,
                                  const std::vector<uint64_t>& ys);

std::vector<uint128_t> KrtwPsuSend(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes);

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes);
