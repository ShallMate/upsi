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

#include <cstdint>
#include <cstring>
#include <memory>
#include <vector>

#include "examples/upsi/psu/krtw19_psu.h"
#include "yacl/base/exception.h"
#include "yacl/utils/serialize.h"

namespace {

constexpr char kKrtwUnionSizeTag[] = "krtw_psu_union_size";
constexpr char kKrtwUnionPayloadTag[] = "krtw_psu_union_payload";

}  // namespace

std::vector<uint128_t> KrtwPsuSend(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  examples::psu::KrtwPsuSend(ctx, elem_hashes);

  const auto union_size = static_cast<size_t>(
      yacl::DeserializeUint128(ctx->Recv(ctx->PrevRank(), kKrtwUnionSizeTag)));
  if (union_size == 0) {
    return {};
  }

  std::vector<uint128_t> union_items(union_size);
  auto union_buf = ctx->Recv(ctx->PrevRank(), kKrtwUnionPayloadTag);
  YACL_ENFORCE(union_buf.size() == int64_t(union_size * sizeof(uint128_t)));
  std::memcpy(union_items.data(), union_buf.data(), union_buf.size());
  return union_items;
}

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  auto union_items = examples::psu::KrtwPsuRecv(ctx, elem_hashes);
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(union_items.size()),
                 kKrtwUnionSizeTag);
  if (!union_items.empty()) {
    ctx->SendAsync(ctx->NextRank(),
                   yacl::ByteContainerView(
                       union_items.data(), union_items.size() * sizeof(uint128_t)),
                   kKrtwUnionPayloadTag);
  }
  return union_items;
}
