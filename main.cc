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

#include <array>
#include <algorithm>
#include <charconv>
#include <cctype>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <future>
#include <iostream>
#include <iterator>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "aPSI.h"
#include "ecdhpsi/ecdh_psi.h"
#include "ecdhpsi/receiver.h"
#include "ecdhpsi/sender.h"
#include "psu/psu.h"
#include "rr22/okvs/baxos.h"
#include "rr22/rr22.h"
#include "upsi.h"
#include "runtime/types.h"
#include "runtime/link.h"

using namespace upsi_runtime::crypto;
using namespace std;

using namespace apsi;

namespace {

// Change this to `PsuProtocol::kKrtw` to run UPSI with the legacy KRTW PSU.
constexpr PsuProtocol kUpSiPsuProtocol = PsuProtocol::kKrtw;
enum class LinkBackend {
  kTcp = 0,
};

constexpr uint64_t kUpSiRecvTimeoutMs = 10 * 60 * 1000;
constexpr size_t kDefaultUpdateCount = 1;

struct RunConfig {
  PsuProtocol protocol = kUpSiPsuProtocol;
  LinkBackend link_backend = LinkBackend::kTcp;
  size_t update_count = kDefaultUpdateCount;
  size_t set_size = 1 << 20;
  size_t update_size = 1 << 9;
  size_t threads = 8;
};

struct UpdateBatch {
  std::vector<uint64_t> add_ids;
  std::vector<uint64_t> sub_ids;
  std::vector<uint128_t> add_items;
  std::vector<uint128_t> sub_items;
};

std::filesystem::path GetExecutableDir() {
  std::error_code ec;
  auto exe_path = std::filesystem::read_symlink("/proc/self/exe", ec);
  if (!ec) {
    return exe_path.parent_path();
  }
  return std::filesystem::current_path(ec);
}

std::string ResolveParamsPath(std::string_view file_name) {
  const auto exe_dir = GetExecutableDir();
  const auto file_path = std::filesystem::path(file_name);
  const std::array<std::filesystem::path, 6> candidates = {
      file_path,
      std::filesystem::path("parameters") / file_path,
      std::filesystem::path("parameters") / file_path,
      exe_dir / "parameters" / file_path,
      exe_dir / "parameters" / file_path,
      exe_dir.parent_path() / "parameters" / file_path,
  };

  for (const auto& candidate : candidates) {
    if (std::filesystem::exists(candidate)) {
      return candidate.string();
    }
  }

  return (std::filesystem::path("parameters") / file_path).string();
}

void ConfigureLinkTimeouts(
    const std::vector<std::shared_ptr<upsi_runtime::link::Context>>& lctxs) {
  for (const auto& lctx : lctxs) {
    lctx->SetRecvTimeout(kUpSiRecvTimeoutMs);
  }
}

std::string ToLowerAscii(std::string_view input) {
  std::string normalized(input);
  for (char& ch : normalized) {
    ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
  }
  return normalized;
}

std::optional<PsuProtocol> ParsePsuProtocol(std::string_view value) {
  const auto normalized = ToLowerAscii(value);
  if (normalized == "krtw") {
    return PsuProtocol::kKrtw;
  }
  if (normalized == "iblt") {
    return PsuProtocol::kIblt;
  }
  return std::nullopt;
}

std::optional<LinkBackend> ParseLinkBackend(std::string_view value) {
  const auto normalized = ToLowerAscii(value);
  if (normalized == "tcp") {
    return LinkBackend::kTcp;
  }
  return std::nullopt;
}

std::optional<size_t> ParsePositiveSize(std::string_view value) {
  if (value.empty()) {
    return std::nullopt;
  }

  size_t parsed = 0;
  const char* begin = value.data();
  const char* end = begin + value.size();
  auto result = std::from_chars(begin, end, parsed);
  if (result.ec != std::errc() || result.ptr != end || parsed == 0) {
    return std::nullopt;
  }
  return parsed;
}

const char* PsuProtocolName(PsuProtocol protocol) {
  switch (protocol) {
    case PsuProtocol::kKrtw:
      return "krtw";
    case PsuProtocol::kIblt:
      return "iblt";
  }
  return "unknown";
}

const char* LinkBackendName(LinkBackend backend) {
  switch (backend) {
    case LinkBackend::kTcp:
      return "tcp";
  }
  return "unknown";
}

void PrintUsage(const char* argv0) {
  std::cout << "Usage: " << argv0
            << " [--psu-backend=krtw|iblt] [--update-count=N]"
               " [--link=tcp] [--set-size=N] [--update-size=N] [--threads=N]"
            << std::endl;
  std::cout << "Environment overrides: UPSI_PSU_BACKEND=krtw|iblt, "
               "UPSI_UPDATE_COUNT=N, UPSI_LINK_BACKEND=tcp"
            << std::endl;
}

RunConfig ResolveRunConfig(int argc, char** argv) {
  RunConfig config;

  if (const char* env = std::getenv("UPSI_PSU_BACKEND")) {
    auto parsed = ParsePsuProtocol(env);
    if (!parsed.has_value()) {
      std::cerr << "Invalid UPSI_PSU_BACKEND: " << env << std::endl;
      PrintUsage(argv[0]);
      std::exit(1);
    }
    config.protocol = *parsed;
  }

  if (const char* env = std::getenv("UPSI_UPDATE_COUNT")) {
    auto parsed = ParsePositiveSize(env);
    if (!parsed.has_value()) {
      std::cerr << "Invalid UPSI_UPDATE_COUNT: " << env << std::endl;
      PrintUsage(argv[0]);
      std::exit(1);
    }
    config.update_count = *parsed;
  }

  if (const char* env = std::getenv("UPSI_LINK_BACKEND")) {
    auto parsed = ParseLinkBackend(env);
    if (!parsed.has_value()) {
      std::cerr << "Invalid UPSI_LINK_BACKEND: " << env << std::endl;
      PrintUsage(argv[0]);
      std::exit(1);
    }
    config.link_backend = *parsed;
  }

  for (int idx = 1; idx < argc; ++idx) {
    std::string_view arg(argv[idx]);
    if (arg == "--help" || arg == "-h") {
      PrintUsage(argv[0]);
      std::exit(0);
    }
    bool numeric = false;
    for (auto [prefix, dest] : std::array<std::pair<std::string_view,size_t*>,3>{{
        {"--set-size=", &config.set_size}, {"--update-size=", &config.update_size}, {"--threads=", &config.threads}}}) {
      if (arg.starts_with(prefix)) {
        auto value=ParsePositiveSize(arg.substr(prefix.size()));
        if (!value) throw std::invalid_argument("invalid positive integer option");
        *dest=*value; numeric=true; break;
      }
    }
    if (numeric) continue;
    constexpr std::string_view kPrefix = "--psu-backend=";
    if (arg.substr(0, kPrefix.size()) == kPrefix) {
      auto parsed = ParsePsuProtocol(arg.substr(kPrefix.size()));
      if (!parsed.has_value()) {
        std::cerr << "Invalid --psu-backend value: "
                  << arg.substr(kPrefix.size()) << std::endl;
        PrintUsage(argv[0]);
        std::exit(1);
      }
      config.protocol = *parsed;
      continue;
    }
    constexpr std::string_view kUpdateCountPrefix = "--update-count=";
    constexpr std::string_view kUpdatesPrefix = "--updates=";
    if (arg.substr(0, kUpdateCountPrefix.size()) == kUpdateCountPrefix) {
      auto parsed = ParsePositiveSize(arg.substr(kUpdateCountPrefix.size()));
      if (!parsed.has_value()) {
        std::cerr << "Invalid --update-count value: "
                  << arg.substr(kUpdateCountPrefix.size()) << std::endl;
        PrintUsage(argv[0]);
        std::exit(1);
      }
      config.update_count = *parsed;
      continue;
    }
    if (arg.substr(0, kUpdatesPrefix.size()) == kUpdatesPrefix) {
      auto parsed = ParsePositiveSize(arg.substr(kUpdatesPrefix.size()));
      if (!parsed.has_value()) {
        std::cerr << "Invalid --updates value: "
                  << arg.substr(kUpdatesPrefix.size()) << std::endl;
        PrintUsage(argv[0]);
        std::exit(1);
      }
      config.update_count = *parsed;
      continue;
    }
    constexpr std::string_view kLinkPrefix = "--link=";
    if (arg.substr(0, kLinkPrefix.size()) == kLinkPrefix) {
      auto parsed = ParseLinkBackend(arg.substr(kLinkPrefix.size()));
      if (!parsed.has_value()) {
        std::cerr << "Invalid --link value: " << arg.substr(kLinkPrefix.size())
                  << std::endl;
        PrintUsage(argv[0]);
        std::exit(1);
      }
      config.link_backend = *parsed;
      continue;
    }

    std::cerr << "Unknown argument: " << arg << std::endl;
    PrintUsage(argv[0]);
    std::exit(1);
  }

  return config;
}

std::vector<uint64_t> CreateRangeIds(uint64_t begin, size_t size) {
  std::vector<uint64_t> ret;
  ret.reserve(size);
  for (size_t idx = 0; idx < size; ++idx) {
    ret.push_back(begin + idx);
  }
  return ret;
}

std::set<uint64_t> CreateRangeIdSet(uint64_t begin, size_t size) {
  auto ids = CreateRangeIds(begin, size);
  return std::set<uint64_t>(ids.begin(), ids.end());
}

std::vector<uint128_t> CreateItemsFromIds(const std::vector<uint64_t>& ids) {
  std::vector<uint128_t> ret;
  ret.reserve(ids.size());
  for (const auto id : ids) {
    ret.push_back(upsi_runtime::crypto::Hash128(std::to_string(id)));
  }
  return ret;
}

std::vector<uint128_t> CreateItemsFromIdSet(const std::set<uint64_t>& ids) {
  return CreateItemsFromIds(std::vector<uint64_t>(ids.begin(), ids.end()));
}

std::set<uint128_t> HashIdSet(const std::set<uint64_t>& ids) {
  auto items = CreateItemsFromIdSet(ids);
  return std::set<uint128_t>(items.begin(), items.end());
}

std::vector<uint64_t> TakeFirstIds(const std::set<uint64_t>& ids,
                                   size_t count) {
  if (ids.size() < count) {
    throw std::runtime_error("not enough current intersection items to delete");
  }

  std::vector<uint64_t> ret;
  ret.reserve(count);
  auto iter = ids.begin();
  for (size_t idx = 0; idx < count; ++idx, ++iter) {
    ret.push_back(*iter);
  }
  return ret;
}

void EraseIds(std::set<uint64_t>& ids, const std::vector<uint64_t>& removed) {
  for (const auto id : removed) {
    ids.erase(id);
  }
}

void InsertIds(std::set<uint64_t>& ids, const std::vector<uint64_t>& added) {
  ids.insert(added.begin(), added.end());
}

UpdateBatch MakeUpdateBatch(size_t round, size_t addnum, size_t subnum,
                            uint64_t add_base,
                            const std::set<uint64_t>& intersection_ids) {
  UpdateBatch batch;
  batch.sub_ids = TakeFirstIds(intersection_ids, subnum);
  batch.add_ids = CreateRangeIds(add_base + round * addnum, addnum);
  batch.sub_items = CreateItemsFromIds(batch.sub_ids);
  batch.add_items = CreateItemsFromIds(batch.add_ids);
  return batch;
}

bool ReportIntersectionCheck(const std::string& label,
                             const std::set<uint128_t>& lhs,
                             const std::set<uint128_t>& rhs) {
  if (lhs == rhs) {
    std::cout << label << " check passed." << std::endl;
    return true;
  }

  std::cout << label << " check failed: lhs=" << lhs.size()
            << ", rhs=" << rhs.size() << std::endl;
  return false;
}

std::vector<std::shared_ptr<upsi_runtime::link::Context>> SetupProtocolWorld(
    LinkBackend backend) {
  switch (backend) {
    case LinkBackend::kTcp:
      return upsi_runtime::link::SetupTcpWorld(2);
  }
  throw std::runtime_error("unknown link backend");
}

}  // namespace

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(upsi_runtime::crypto::Hash128(std::to_string(begin + i)));
  }
  return ret;
}

std::vector<std::string> CreateRangeItemsDH(size_t begin, size_t size) {
  std::vector<std::string> ret;
  for (size_t i = 0; i < size; i++) {
    ret.push_back(std::to_string(begin + i));
  }
  return ret;
}

void RunUPSIv1(const RunConfig& config) {
  const auto update_count=config.update_count;
  const auto link_backend=config.link_backend;
  const uint64_t num = config.set_size;
  const uint64_t addnum = config.update_size;
  const uint64_t subnum = config.update_size;
  if(num < 4*addnum || num > (1<<20) || addnum > 512) throw std::invalid_argument("require 4*update-size <= set-size <= 1048576 and update-size <= 512");
  omp_set_num_threads(config.threads);
  upsi_runtime::parallel_threads=config.threads;
  const uint64_t add_base = num * 2;
  std::cout << "|X| = |Y|:  " << num << std::endl;
  std::cout << "|X^+| = |Y^+|:  " << addnum << std::endl;
  std::cout << "|X^-| = |Y^-|:  " << subnum << std::endl;
  std::cout << "update_count:  " << update_count << std::endl;
  std::cout << "Update count: " << update_count << std::endl;
  size_t bin_size = num;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  ThreadPoolMgr::SetThreadCount(config.threads);
  upsi_runtime::crypto::Prg<uint128_t> prng(upsi_runtime::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(upsi_runtime::MakeSpan(&seed, 1));
  std::cout << "items_num:, bin_size: " << num << ", " << bin_size << std::endl;
  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  std::cout << "baxos.size():  " << baxos.size() << std::endl;
  std::set<uint64_t> x_ids = CreateRangeIdSet(addnum, num);
  std::set<uint64_t> y_ids = CreateRangeIdSet(num / 2, num);
  std::set<uint64_t> intersection_ids;
  std::set_intersection(
      x_ids.begin(), x_ids.end(), y_ids.begin(), y_ids.end(),
      std::inserter(intersection_ids, intersection_ids.begin()));

  std::vector<uint128_t> X = CreateItemsFromIdSet(x_ids);
  std::vector<uint128_t> Y = CreateItemsFromIdSet(y_ids);
  auto start_time = std::chrono::high_resolution_clock::now();
  APSI instanceX(ResolveParamsPath("1M-512-com.json"));
  APSI instanceY(ResolveParamsPath("1M-512-com.json"));
  instanceX.insertItems(X);
  instanceY.insertItems(Y);
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Setup time: " << duration.count() << " seconds" << std::endl;
  auto lctxs = SetupProtocolWorld(link_backend);  // setup network
  ConfigureLinkTimeouts(lctxs);
  instanceY.UseLinkChannel(lctxs[0], lctxs[0]->NextRank());
  instanceX.UseLinkChannel(lctxs[1], lctxs[1]->NextRank());
  auto start_time_base = std::chrono::high_resolution_clock::now();
  std::future<std::vector<uint128_t>> rr22_sender = std::async(
      std::launch::async, [&] { return BasePsiSend(lctxs[0], X, baxos); });
  std::future<std::vector<uint128_t>> rr22_receiver = std::async(
      std::launch::async, [&] { return BasePsiRecv(lctxs[1], Y, baxos); });
  auto psi_result_sender = rr22_sender.get();
  auto psi_result = rr22_receiver.get();
  auto end_time_base = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration_base = end_time_base - start_time_base;
  std::cout << "Base PSI time: " << duration_base.count() << " seconds"
            << std::endl;
  std::set<uint128_t> intersection_sender(psi_result_sender.begin(),
                                          psi_result_sender.end());
  std::set<uint128_t> intersection_receiver(psi_result.begin(),
                                            psi_result.end());
  std::cout << "Base PSI intersection size = " << intersection_receiver.size()
            << std::endl;
  if (intersection_sender == intersection_receiver) {
    std::cout << "The base PSI finish." << std::endl;
  } else {
    std::cout << "The base PSI error." << std::endl;
  }
  const auto expected_base_intersection = HashIdSet(intersection_ids);
  if (!ReportIntersectionCheck("Base PSI sender expected intersection",
                               intersection_sender,
                               expected_base_intersection) ||
      !ReportIntersectionCheck("Base PSI receiver expected intersection",
                               intersection_receiver,
                               expected_base_intersection)) {
    throw std::runtime_error("base PSI result does not match expected state");
  }
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };

  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Base PSI Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Base PSI Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Base PSI Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Base PSI Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Base PSI Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;

  size_t c1 = sender_stats->sent_bytes.load();
  size_t c2 = sender_stats->recv_bytes.load();

  double total_update_seconds = 0.0;
  for (size_t round = 0; round < update_count; ++round) {
    auto batch = MakeUpdateBatch(round, addnum, subnum, add_base,
                                 intersection_ids);
    std::cout << "Update round " << (round + 1) << "/" << update_count
              << std::endl;

    auto sender_stats_before = lctxs[0]->GetStats();
    const size_t round_sent_before = sender_stats_before->sent_bytes.load();
    const size_t round_recv_before = sender_stats_before->recv_bytes.load();
    auto start_time1 = std::chrono::high_resolution_clock::now();

    instanceX.deleteItems(batch.sub_items);
    instanceX.insertItems(batch.add_items);
    instanceY.deleteItems(batch.sub_items);
    instanceY.insertItems(batch.add_items);
    EraseIds(x_ids, batch.sub_ids);
    EraseIds(y_ids, batch.sub_ids);
    EraseIds(intersection_ids, batch.sub_ids);
    InsertIds(x_ids, batch.add_ids);
    InsertIds(y_ids, batch.add_ids);
    InsertIds(intersection_ids, batch.add_ids);

    std::future<std::vector<uint128_t>> upsisender =
        std::async(std::launch::async, [&] {
          return UPsiSendV1(lctxs[0], batch.add_items, batch.sub_items,
                            instanceY, intersection_sender);
        });

    std::future<std::vector<uint128_t>> upsireceiver =
        std::async(std::launch::async, [&] {
          return UPsiRecvV1(lctxs[1], batch.add_items, batch.sub_items,
                            instanceX, intersection_receiver);
        });
    auto upsi_result_sender = upsisender.get();
    auto upsi_result_receiver = upsireceiver.get();
    auto end_time1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> duration1 = end_time1 - start_time1;
    total_update_seconds += duration1.count();

    intersection_sender =
        std::set<uint128_t>(upsi_result_sender.begin(), upsi_result_sender.end());
    intersection_receiver = std::set<uint128_t>(upsi_result_receiver.begin(),
                                                upsi_result_receiver.end());
    const auto expected_intersection = HashIdSet(intersection_ids);
    const bool parties_match = upsi_result_sender == upsi_result_receiver;
    const bool sender_matches_expected =
        ReportIntersectionCheck("UPSI round sender expected intersection",
                                intersection_sender, expected_intersection);
    const bool receiver_matches_expected =
        ReportIntersectionCheck("UPSI round receiver expected intersection",
                                intersection_receiver, expected_intersection);
    if (parties_match && sender_matches_expected && receiver_matches_expected) {
      std::cout << "The uPSI round " << (round + 1) << " finish."
                << std::endl;
    } else {
      std::cout << "The uPSI round " << (round + 1) << " error."
                << std::endl;
      throw std::runtime_error("uPSI update result does not match expected state");
    }

    auto sender_stats_after = lctxs[0]->GetStats();
    const size_t round_sent =
        sender_stats_after->sent_bytes.load() - round_sent_before;
    const size_t round_recv =
        sender_stats_after->recv_bytes.load() - round_recv_before;
    std::cout << "UPSI round " << (round + 1) << " time: "
              << duration1.count() << " seconds" << std::endl;
    std::cout << "UPSI round " << (round + 1)
              << " Total Communication: "
              << bytesToMB(round_sent) + bytesToMB(round_recv) << " MB"
              << std::endl;
  }

  std::cout << "The uPSI finish." << std::endl;
  std::cout << "UPSI time: " << total_update_seconds << " seconds"
            << std::endl;
  auto sender_stats1 = lctxs[0]->GetStats();
  size_t c5 = sender_stats1->sent_bytes.load() - c1;
  size_t c6 = sender_stats1->recv_bytes.load() - c2;
  std::cout << "UPSI Total Communication: " << bytesToMB(c5) + bytesToMB(c6)
            << " MB" << std::endl;
}

int main(int argc, char** argv) {
  const auto config = ResolveRunConfig(argc, argv);
  SetDefaultPsuProtocol(config.protocol);
  std::cout << "PSU backend: " << PsuProtocolName(config.protocol)
            << std::endl;
  std::cout << "Link backend: " << LinkBackendName(config.link_backend)
            << std::endl;
  RunUPSIv1(config);
}
