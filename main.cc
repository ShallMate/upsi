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
#include <cctype>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#include "examples/upsi/aPSI.h"
#include "examples/upsi/ecdhpsi/ecdh_psi.h"
#include "examples/upsi/ecdhpsi/receiver.h"
#include "examples/upsi/ecdhpsi/sender.h"
#include "examples/upsi/psu/psu.h"
#include "examples/upsi/rr22/okvs/baxos.h"
#include "examples/upsi/rr22/rr22.h"
#include "examples/upsi/upsi.h"
#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"

using namespace yacl::crypto;
using namespace std;

using namespace apsi;

namespace {

// Change this to `PsuProtocol::kKrtw` to run UPSI with the legacy KRTW PSU.
constexpr PsuProtocol kUpSiPsuProtocol = PsuProtocol::kKrtw;
constexpr uint64_t kUpSiRecvTimeoutMs = 10 * 60 * 1000;

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
      std::filesystem::path("examples/upsi/parameters") / file_path,
      exe_dir / "parameters" / file_path,
      exe_dir / "examples/upsi/parameters" / file_path,
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
    const std::vector<std::shared_ptr<yacl::link::Context>>& lctxs) {
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

const char* PsuProtocolName(PsuProtocol protocol) {
  switch (protocol) {
    case PsuProtocol::kKrtw:
      return "krtw";
    case PsuProtocol::kIblt:
      return "iblt";
  }
  return "unknown";
}

void PrintUsage(const char* argv0) {
  std::cout << "Usage: " << argv0 << " [--psu-backend=krtw|iblt]" << std::endl;
  std::cout << "Environment override: UPSI_PSU_BACKEND=krtw|iblt"
            << std::endl;
}

PsuProtocol ResolvePsuProtocol(int argc, char** argv) {
  PsuProtocol protocol = kUpSiPsuProtocol;

  if (const char* env = std::getenv("UPSI_PSU_BACKEND")) {
    auto parsed = ParsePsuProtocol(env);
    if (!parsed.has_value()) {
      std::cerr << "Invalid UPSI_PSU_BACKEND: " << env << std::endl;
      PrintUsage(argv[0]);
      std::exit(1);
    }
    protocol = *parsed;
  }

  for (int idx = 1; idx < argc; ++idx) {
    std::string_view arg(argv[idx]);
    if (arg == "--help" || arg == "-h") {
      PrintUsage(argv[0]);
      std::exit(0);
    }
    constexpr std::string_view kPrefix = "--psu-backend=";
    if (arg.substr(0, kPrefix.size()) == kPrefix) {
      auto parsed = ParsePsuProtocol(arg.substr(kPrefix.size()));
      if (!parsed.has_value()) {
        std::cerr << "Invalid --psu-backend value: "
                  << arg.substr(kPrefix.size()) << std::endl;
        PrintUsage(argv[0]);
        std::exit(1);
      }
      protocol = *parsed;
      continue;
    }

    std::cerr << "Unknown argument: " << arg << std::endl;
    PrintUsage(argv[0]);
    std::exit(1);
  }

  return protocol;
}

}  // namespace

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
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

void RunRR22() {
  const uint64_t num = 1 << 22;
  size_t bin_size = num;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);
  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items_a = CreateRangeItems(0, num);
  std::vector<uint128_t> items_b = CreateRangeItems(10, num);

  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  ConfigureLinkTimeouts(lctxs);

  auto start_time = std::chrono::high_resolution_clock::now();

  std::future<std::vector<uint128_t>> rr22_sender =
      std::async(std::launch::async,
                 [&] { return rr22::RR22PsiSend(lctxs[0], items_a, baxos); });

  std::future<std::vector<uint128_t>> rr22_receiver =
      std::async(std::launch::async,
                 [&] { return rr22::RR22PsiRecv(lctxs[1], items_b, baxos); });

  auto psi_result_sender = rr22_sender.get();
  auto psi_result = rr22_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;

  std::sort(psi_result.begin(), psi_result.end());
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
}

void RunUPSI() {
  const uint64_t num = 1 << 17;
  const uint64_t addnum = 1 << 8;
  const uint64_t subnum = 1 << 8;
  SPDLOG_INFO("|X| = |Y|: {}", num);
  SPDLOG_INFO("|X^+| = |Y^+|: {}", addnum);
  SPDLOG_INFO("|X^-| = |Y^-|: {}", subnum);
  size_t bin_size = num;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);
  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> X = CreateRangeItems(addnum, num);
  std::vector<uint128_t> Y = CreateRangeItems(num / 2, num);
  std::vector<uint128_t> Xadd = CreateRangeItems(0, addnum);
  std::vector<uint128_t> Yadd = CreateRangeItems(0, addnum);
  std::vector<uint128_t> Xsub = CreateRangeItems(num - subnum, subnum);
  std::vector<uint128_t> Ysub = CreateRangeItems(num - subnum, subnum);
  auto start_time = std::chrono::high_resolution_clock::now();
  EcdhReceiver yaddreceiver;
  EcdhSender yaddsender;
  yaddsender.UpdatePRFs(absl::MakeSpan(X));
  EcdhReceiver xaddreceiver;
  EcdhSender xaddsender;
  xaddsender.UpdatePRFs(absl::MakeSpan(Y));
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Setup time: " << duration.count() << " seconds" << std::endl;
  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
  ConfigureLinkTimeouts(lctxs);
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
  size_t c3 = receiver_stats->sent_bytes.load();
  size_t c4 = receiver_stats->recv_bytes.load();

  auto start_time1 = std::chrono::high_resolution_clock::now();
  std::future<std::vector<uint128_t>> upsisender =
      std::async(std::launch::async, [&] {
        return UPsiSend(lctxs[0], Y, Yadd, Ysub, yaddreceiver, xaddsender,
                        intersection_sender);
      });

  std::future<std::vector<uint128_t>> upsireceiver =
      std::async(std::launch::async, [&] {
        return UPsiRecv(lctxs[1], X, Xadd, Xsub, xaddreceiver, yaddsender,
                        intersection_receiver);
      });
  auto upsi_result_sender = upsisender.get();
  auto upsi_result_receiver = upsireceiver.get();
  auto end_time1 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration1 = end_time1 - start_time1;
  std::set<uint128_t> upsi_intersection_sender(upsi_result_sender.begin(),
                                               upsi_result_sender.end());
  std::set<uint128_t> upsi_intersection_receiver(upsi_result_receiver.begin(),
                                                 upsi_result_receiver.end());
  if (upsi_result_sender == upsi_result_receiver) {
    std::cout << "The uPSI finish." << std::endl;
  } else {
    std::cout << "The uPSI error." << std::endl;
  }
  std::cout << "UPSI time: " << duration1.count() << " seconds" << std::endl;
  auto sender_stats1 = lctxs[0]->GetStats();
  auto receiver_stats1 = lctxs[1]->GetStats();
  size_t c5 = sender_stats1->sent_bytes.load() - c1;
  size_t c6 = sender_stats1->recv_bytes.load() - c2;
  size_t c7 = receiver_stats1->sent_bytes.load() - c3;
  size_t c8 = receiver_stats1->recv_bytes.load() - c4;
  std::cout << "UPSI Sender sent bytes: " << bytesToMB(c5) << " MB"
            << std::endl;
  std::cout << "UPSI Sender received bytes: " << bytesToMB(c6) << " MB"
            << std::endl;
  std::cout << "UPSI Receiver sent bytes: " << bytesToMB(c7) << " MB"
            << std::endl;
  std::cout << "UPSI Receiver received bytes: " << bytesToMB(c8) << " MB"
            << std::endl;
  std::cout << "UPSI Total Communication: " << bytesToMB(c5) + bytesToMB(c6)
            << " MB" << std::endl;
}

int RunPsuDemo() {
  const int kWorldSize = 2;
  auto contexts = yacl::link::test::SetupWorld(kWorldSize);
  auto n = 1 << 10;
  std::vector<uint128_t> items_a = CreateRangeItems(0, n);
  std::vector<uint128_t> items_b = CreateRangeItems(1, n);
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<std::vector<uint128_t>> psu_sender = std::async(
      std::launch::async, [&] { return PsuSend(contexts[0], items_a); });
  std::future<std::vector<uint128_t>> psu_receiver = std::async(
      std::launch::async, [&] { return PsuRecv(contexts[1], items_b); });
  psu_sender.get();
  auto psu_result = psu_receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  std::sort(psu_result.begin(), psu_result.end());
  std::set<uint128_t> union_set;
  union_set.insert(items_a.begin(), items_a.end());
  union_set.insert(items_b.begin(), items_b.end());
  std::vector<uint128_t> union_vec(union_set.begin(), union_set.end());

  if (psu_result == union_vec) {
    std::cout << "Test passed!" << std::endl;
  } else {
    std::cout << "Test failed!" << std::endl;
    std::cout << "Expected: ";
    for (const auto& elem : union_vec) {
      std::cout << elem << " ";
    }
    std::cout << std::endl;
    std::cout << "Got: ";
    for (const auto& elem : psu_result) {
      std::cout << elem << " ";
    }
    std::cout << std::endl;
  }
  auto sender_stats = contexts[0]->GetStats();
  auto receiver_stats = contexts[1]->GetStats();

  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };

  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int RunEcdhPsi() {
  size_t s_n = 1 << 20;
  size_t r_n = 1 << 20;
  auto x = CreateRangeItemsDH(0, s_n);
  auto y = CreateRangeItemsDH(3, r_n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> sender =
      std::async(std::launch::async, [&] { EcdhPsiSend(lctxs[0], x, r_n); });
  std::future<std::vector<size_t>> receiver = std::async(
      std::launch::async, [&] { return EcdhPsiRecv(lctxs[1], y, s_n); });
  sender.get();
  auto z = receiver.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;
  std::cout << "The intersection size is " << z.size() << std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int RunAEcdhPsi() {
  size_t s_n = 1 << 19;
  size_t r_n = 1 << 2;
  auto x = CreateRangeItems(200, s_n);
  // auto xadd = CreateRangeItems(100, 100);
  auto y = CreateRangeItems(100, r_n);
  auto lctxs = yacl::link::test::SetupWorld(2);  // setup network
  EcdhReceiver receiver;
  EcdhSender sender;
  sender.UpdatePRFs(absl::MakeSpan(x));
  // sender.UpdatePRFs(absl::MakeSpan(xadd));
  auto start_time = std::chrono::high_resolution_clock::now();
  std::future<void> sendertask = std::async(
      std::launch::async, [&] { sender.EcdhPsiSend(lctxs[0], r_n); });
  std::future<std::vector<uint128_t>> receivertask = std::async(
      std::launch::async, [&] { return receiver.EcdhPsiRecv(lctxs[1], y); });
  sendertask.get();
  auto z = receivertask.get();
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  ;
  std::cout << "The intersection size is " << z.size() << std::endl;
  auto bytesToMB = [](size_t bytes) -> double {
    return static_cast<double>(bytes) / (1024 * 1024);
  };
  auto sender_stats = lctxs[0]->GetStats();
  auto receiver_stats = lctxs[1]->GetStats();
  std::cout << "Sender sent bytes: "
            << bytesToMB(sender_stats->sent_bytes.load()) << " MB" << std::endl;
  std::cout << "Sender received bytes: "
            << bytesToMB(sender_stats->recv_bytes.load()) << " MB" << std::endl;
  std::cout << "Receiver sent bytes: "
            << bytesToMB(receiver_stats->sent_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Receiver received bytes: "
            << bytesToMB(receiver_stats->recv_bytes.load()) << " MB"
            << std::endl;
  std::cout << "Total Communication: "
            << bytesToMB(receiver_stats->sent_bytes.load()) +
                   bytesToMB(receiver_stats->recv_bytes.load())
            << " MB" << std::endl;
  return 0;
}

int RunAPSI() {
  // Use the maximum number of threads available on the machine
  // ThreadPoolMgr::SetThreadCount(std::thread::hardware_concurrency());
  ThreadPoolMgr::SetThreadCount(std::thread::hardware_concurrency());
  // Full logging to console
  // Log::SetLogLevel(Log::Level::all);
  // Log::SetConsoleDisabled(false);
  size_t ns = 1 << 22;
  size_t nr = 1 << 8;
  std::vector<uint128_t> raw_sender_items = CreateRangeItems(1, ns);
  APSI instance(ResolveParamsPath("16M-256.json"));
  instance.insertItems(raw_sender_items);
  // instance.printParams();
  vector<uint128_t> raw_receiver_items = CreateRangeItems(1, nr);
  auto start_time = std::chrono::high_resolution_clock::now();
  auto intersection = instance.APsiRun(raw_receiver_items);
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Intersection size: " << intersection.size() << std::endl;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  cout << "Communication bytes: "
       << instance.channel_->bytes_received() / (1024.0 * 1024.0) << " MB"
       << endl;
  return 0;
}

void RunUPSIv1() {
  const uint64_t num = 1 << 20;
  const uint64_t addnum = 1 << 9;
  const uint64_t subnum = 1 << 9;
  SPDLOG_INFO("|X| = |Y|: {}", num);
  SPDLOG_INFO("|X^+| = |Y^+|: {}", addnum);
  SPDLOG_INFO("|X^-| = |Y^-|: {}", subnum);
  size_t bin_size = num;
  size_t weight = 3;
  size_t ssp = 40;
  okvs::Baxos baxos;
  ThreadPoolMgr::SetThreadCount(std::thread::hardware_concurrency());
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));
  SPDLOG_INFO("items_num:{}, bin_size:{}", num, bin_size);
  baxos.Init(num, bin_size, weight, ssp, okvs::PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());
  std::vector<uint128_t> X = CreateRangeItems(addnum, num);
  std::vector<uint128_t> Y = CreateRangeItems(num / 2, num);
  std::vector<uint128_t> Xadd = CreateRangeItems(0, addnum);
  std::vector<uint128_t> Yadd = CreateRangeItems(0, addnum);
  std::vector<uint128_t> Xsub = CreateRangeItems(num - subnum, subnum);
  std::vector<uint128_t> Ysub = CreateRangeItems(num - subnum, subnum);
  auto start_time = std::chrono::high_resolution_clock::now();
  APSI instanceX(ResolveParamsPath("1M-512-com.json"));
  APSI instanceY(ResolveParamsPath("1M-512-com.json"));
  instanceX.insertItems(X);
  instanceY.insertItems(Y);
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Setup time: " << duration.count() << " seconds" << std::endl;
  auto lctxs = yacl::link::test::SetupBrpcWorld(2);  // setup network
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

  auto start_time1 = std::chrono::high_resolution_clock::now();
  instanceX.deleteItems(Xsub);
  instanceX.insertItems(Xadd);
  instanceY.deleteItems(Ysub);
  instanceY.insertItems(Yadd);
  std::future<std::vector<uint128_t>> upsisender =
      std::async(std::launch::async, [&] {
        return UPsiSendV1(lctxs[0], Y, Yadd, Ysub, instanceY,
                          intersection_sender);
      });

  std::future<std::vector<uint128_t>> upsireceiver =
      std::async(std::launch::async, [&] {
        return UPsiRecvV1(lctxs[1], X, Xadd, Xsub, instanceX,
                          intersection_receiver);
      });
  auto upsi_result_sender = upsisender.get();
  auto upsi_result_receiver = upsireceiver.get();
  auto end_time1 = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration1 = end_time1 - start_time1;
  std::set<uint128_t> upsi_intersection_sender(upsi_result_sender.begin(),
                                               upsi_result_sender.end());
  std::set<uint128_t> upsi_intersection_receiver(upsi_result_receiver.begin(),
                                                 upsi_result_receiver.end());
  if (upsi_result_sender == upsi_result_receiver) {
    std::cout << "The uPSI finish." << std::endl;
  } else {
    std::cout << "The uPSI error." << std::endl;
  }
  std::cout << "UPSI time: " << duration1.count() << " seconds" << std::endl;
  auto sender_stats1 = lctxs[0]->GetStats();
  auto receiver_stats1 = lctxs[1]->GetStats();
  size_t c5 = sender_stats1->sent_bytes.load() - c1;
  size_t c6 = sender_stats1->recv_bytes.load() - c2;
  std::cout << "UPSI Total Communication: " << bytesToMB(c5) + bytesToMB(c6)
            << " MB" << std::endl;
}

int main(int argc, char** argv) {
  const auto protocol = ResolvePsuProtocol(argc, argv);
  SetDefaultPsuProtocol(protocol);
  std::cout << "PSU backend: " << PsuProtocolName(protocol) << std::endl;
  // RunUPSI();
  // RunAEcdhPsi();
  // RunAPSI();
  RunUPSIv1();
  // RunPsuDemo();
}
