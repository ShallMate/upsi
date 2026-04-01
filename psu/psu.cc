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

#include <array>
#include <atomic>
#include <cstring>
#include <memory>
#include <mutex>
#include <optional>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>

#include "coproto/Socket/LocalAsyncSock.h"
#include "coproto/coproto.h"
#include "examples/upsi/psu/krtw19_psu.h"
#include "examples/upsi/psu/iblt_based_psu/psu.h"
#include "yacl/base/exception.h"
#include "yacl/utils/serialize.h"

namespace {

using Item = psu::Item;
using ItemSet = psu::ItemSet;
using LocalSocket = coproto::LocalAsyncSocket;
using macoro::sync_wait;
using macoro::when_all_ready;

std::atomic<PsuProtocol> g_default_psu_protocol{PsuProtocol::kIblt};

constexpr double kIbltMultFactor = 1.5;
constexpr size_t kSoftspokenOtFieldSize = 2;
constexpr bool kOprfReducedRounds = false;
constexpr uint64_t kIbltSeedHi = 123;
constexpr uint64_t kIbltSeedLo = 456;
constexpr char kKrtwUnionSizeTag[] = "krtw_psu_union_size";
constexpr char kKrtwUnionPayloadTag[] = "krtw_psu_union_payload";

enum class Role {
  kSender = 0,
  kReceiver = 1,
};

Item Uint128ToItem(uint128_t value) {
  const auto [hi, lo] = yacl::DecomposeUInt128(value);
  return Item(hi, lo);
}

uint128_t ItemToUint128(const Item& item) {
  const auto words = item.get<uint64_t>();
  return yacl::MakeUint128(words[1], words[0]);
}

std::vector<uint128_t> ItemSetToUint128Vec(const ItemSet& items) {
  std::vector<uint128_t> out;
  out.reserve(items.size());
  for (const auto& item : items) {
    out.push_back(ItemToUint128(item));
  }
  return out;
}

ItemSet BuildItemSet(const std::vector<uint128_t>& elem_hashes) {
  ItemSet items;
  items.reserve(elem_hashes.size());
  for (const auto& elem : elem_hashes) {
    items.insert(Uint128ToItem(elem));
  }
  return items;
}

osuCrypto::block RandomBlock() {
  thread_local std::mt19937_64 gen(std::random_device{}());
  return osuCrypto::block(gen(), gen());
}

std::string MakeSessionKey(const std::shared_ptr<yacl::link::Context>& ctx) {
  std::string key = ctx->Id();
  key.append(":").append(ctx->NextId());
  for (size_t i = 0; i < ctx->WorldSize(); ++i) {
    key.append(":").append(ctx->PartyIdByRank(i));
  }
  return key;
}

class LocalSocketRegistry {
 public:
  static LocalSocketRegistry& Instance() {
    static LocalSocketRegistry registry;
    return registry;
  }

  LocalSocket Acquire(const std::string& session_key, Role role) {
    std::lock_guard<std::mutex> lock(mu_);
    auto& slot = sessions_[session_key];
    if (!slot[0].has_value() && !slot[1].has_value()) {
      auto pair = LocalSocket::makePair();
      slot[0].emplace(std::move(pair[0]));
      slot[1].emplace(std::move(pair[1]));
    }

    const size_t idx = static_cast<size_t>(role);
    YACL_ENFORCE(slot[idx].has_value(), "missing local socket for role={}", idx);

    auto sock = std::move(*slot[idx]);
    slot[idx].reset();
    if (!slot[0].has_value() && !slot[1].has_value()) {
      sessions_.erase(session_key);
    }
    return sock;
  }

 private:
  std::mutex mu_;
  std::unordered_map<std::string, std::array<std::optional<LocalSocket>, 2>>
      sessions_;
};

size_t ExchangeSetSize(const std::shared_ptr<yacl::link::Context>& ctx,
                       size_t local_size) {
  ctx->SendAsync(ctx->NextRank(), yacl::SerializeUint128(local_size),
                 "iblt_psu_set_size");
  return static_cast<size_t>(
      yacl::DeserializeUint128(ctx->Recv(ctx->PrevRank(), "iblt_psu_set_size")));
}

void MergeSocketStats(const std::shared_ptr<yacl::link::Context>& ctx,
                      LocalSocket& sock) {
  ctx->stats_->sent_bytes.fetch_add(sock.bytesSent(), std::memory_order_relaxed);
  ctx->stats_->recv_bytes.fetch_add(sock.bytesReceived(),
                                    std::memory_order_relaxed);
  ctx->stats_->sent_actions.fetch_add(1, std::memory_order_relaxed);
  ctx->stats_->recv_actions.fetch_add(1, std::memory_order_relaxed);
}

std::vector<uint128_t> RunIbltPsu(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes, Role role) {
  auto items = BuildItemSet(elem_hashes);
  const size_t peer_size = ExchangeSetSize(ctx, items.size());
  const std::string session_key = MakeSessionKey(ctx);
  auto sock = LocalSocketRegistry::Instance().Acquire(session_key, role);
  ItemSet union_items;
  const auto iblt_seed = osuCrypto::block(kIbltSeedHi, kIbltSeedLo);

  if (role == Role::kSender) {
    psu::Sender sender(RandomBlock(), items.size(), peer_size, iblt_seed,
                       kIbltMultFactor, kSoftspokenOtFieldSize,
                       kOprfReducedRounds);
    auto setup_task = sender.setup(sock, items);
    sync_wait(when_all_ready(std::move(setup_task)));
    auto send_task = sender.send(sock, union_items);
    sync_wait(when_all_ready(std::move(send_task)));
  } else {
    psu::Receiver receiver(RandomBlock(), items.size(), peer_size, iblt_seed,
                           kIbltMultFactor, kSoftspokenOtFieldSize,
                           kOprfReducedRounds);
    auto setup_task = receiver.setup(sock, items);
    sync_wait(when_all_ready(std::move(setup_task)));
    auto recv_task = receiver.recv(sock, union_items);
    sync_wait(when_all_ready(std::move(recv_task)));
  }

  sync_wait(when_all_ready(sock.flush()));
  MergeSocketStats(ctx, sock);
  return ItemSetToUint128Vec(union_items);
}

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
      return IbltPsuSend(ctx, elem_hashes);
    case PsuProtocol::kKrtw:
      return KrtwPsuSend(ctx, elem_hashes);
  }
  YACL_THROW("unsupported PSU protocol");
}

std::vector<uint128_t> PsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  switch (GetDefaultPsuProtocol()) {
    case PsuProtocol::kIblt:
      return IbltPsuRecv(ctx, elem_hashes);
    case PsuProtocol::kKrtw:
      return KrtwPsuRecv(ctx, elem_hashes);
  }
  YACL_THROW("unsupported PSU protocol");
}

std::vector<uint128_t> IbltPsuSend(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  return RunIbltPsu(ctx, elem_hashes, Role::kSender);
}

std::vector<uint128_t> IbltPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes) {
  return RunIbltPsu(ctx, elem_hashes, Role::kReceiver);
}

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
