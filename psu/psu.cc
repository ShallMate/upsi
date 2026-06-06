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

#include "examples/upsi/psu/psu.h"

#include <atomic>
#include <memory>
#include <vector>

#include "yacl/base/exception.h"

namespace {

#if defined(UPSI_PSU_ENABLE_KRTW)
constexpr PsuProtocol kCompiledDefaultProtocol = PsuProtocol::kKrtw;
#elif defined(UPSI_PSU_ENABLE_IBLT)
constexpr PsuProtocol kCompiledDefaultProtocol = PsuProtocol::kIblt;
#else
#error "A PSU backend must be enabled for this target"
#endif

std::atomic<PsuProtocol> g_default_psu_protocol{kCompiledDefaultProtocol};

}  // namespace

void SetDefaultPsuProtocol(PsuProtocol protocol) {
  g_default_psu_protocol.store(protocol, std::memory_order_relaxed);
}

PsuProtocol GetDefaultPsuProtocol() {
  return g_default_psu_protocol.load(std::memory_order_relaxed);
}

std::vector<uint128_t> PsuSend(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  switch (GetDefaultPsuProtocol()) {
    case PsuProtocol::kIblt:
#ifdef UPSI_PSU_ENABLE_IBLT
      return IbltPsuSend(ctx, elem_hashes);
#else
      break;
#endif
    case PsuProtocol::kKrtw:
#ifdef UPSI_PSU_ENABLE_KRTW
      return KrtwPsuSend(ctx, elem_hashes);
#else
      break;
#endif
  }
  YACL_THROW("selected PSU protocol is not linked into this target");
}

std::vector<uint128_t> PsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  switch (GetDefaultPsuProtocol()) {
    case PsuProtocol::kIblt:
#ifdef UPSI_PSU_ENABLE_IBLT
      return IbltPsuRecv(ctx, elem_hashes);
#else
      break;
#endif
    case PsuProtocol::kKrtw:
#ifdef UPSI_PSU_ENABLE_KRTW
      return KrtwPsuRecv(ctx, elem_hashes);
#else
      break;
#endif
  }
  YACL_THROW("selected PSU protocol is not linked into this target");
}
