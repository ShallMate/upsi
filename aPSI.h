
// Copyright 2025 Guowei Ling
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
#include <apsi/network/stream_channel.h>
#include <apsi/sender.h>

#include <fstream>
#include <iostream>
#include <memory>
#include <optional>
#include <string>

#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

inline std::vector<std::string> ItemsToStr(std::vector<uint128_t>& items) {
  std::vector<std::string> ret(items.size());
  yacl::parallel_for(0, items.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      ret[idx] = yacl::SerializeUint128(items[idx]);
    }
  });
  return ret;
}

class APSI {
 public:
  explicit APSI(const std::string& params_path) {
    // 读取 params.json 配置文件
    std::ifstream params_fs(params_path, std::ios::in);
    if (!params_fs.is_open()) {
      std::cerr << "Failed to open " << params_path << " file." << std::endl;
      throw std::runtime_error("Failed to open params file");
    }
    params_content_.assign((std::istreambuf_iterator<char>(params_fs)),
                           std::istreambuf_iterator<char>());

    // **延迟初始化** PSIParams
    params_ = apsi::PSIParams::Load(params_content_);

    // 初始化流通道
    channel_stream_ = std::make_unique<std::stringstream>();
    channel_ = std::make_unique<apsi::network::StreamChannel>(*channel_stream_);
    // Insert the items in the SenderDB
    sender_db = std::make_shared<apsi::sender::SenderDB>(*params_);
  }

  void printParams() const {
    std::cout << "Params content: " << params_content_ << std::endl;
  }

  void insertItems(std::vector<uint128_t>& items) {
    std::vector<std::string> raw_sender_items_str = ItemsToStr(items);
    // We need to convert the strings to Item objects
    std::vector<apsi::Item> sender_items(raw_sender_items_str.begin(),
                                         raw_sender_items_str.end());
    // Insert the items in the SenderDB
    sender_db->insert_or_assign(sender_items);
  }

  void deleteItems(std::vector<uint128_t>& items) {
    std::vector<std::string> raw_sender_items_str = ItemsToStr(items);
    // We need to convert the strings to Item objects
    std::vector<apsi::Item> sender_items(raw_sender_items_str.begin(),
                                         raw_sender_items_str.end());
    // Insert the items in the SenderDB
    sender_db->remove(sender_items);
  }

  std::unique_ptr<std::stringstream> channel_stream_;
  std::unique_ptr<apsi::network::StreamChannel> channel_;
  std::string params_content_;
  std::optional<apsi::PSIParams> params_;  // 允许先初始化内容，再创建对象
  std::shared_ptr<apsi::sender::SenderDB> sender_db;
  apsi::sender::Query query;
  std::vector<uint128_t> APsiRun(std::vector<uint128_t>& items);
  std::vector<uint128_t> RunQuery(
      apsi::sender::Query query,
      const std::pair<std::vector<apsi::HashedItem>,
                      std::vector<apsi::LabelKey>>& receiver_oprf_items,
      std::vector<uint128_t>& items);
};
