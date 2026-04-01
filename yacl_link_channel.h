// Copyright 2026 Guowei Ling.
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

#include <cstdint>
#include <mutex>
#include <memory>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

#include <apsi/network/channel.h>
#include <apsi/network/stream_channel.h>

#include "yacl/link/context.h"

namespace apsi::network {

// Bridge APSI's Channel API onto yacl::link::Context so APSI traffic follows
// the same BRPC/localhost path as the rest of the protocol.
class YaclLinkChannel final : public Channel {
 public:
  YaclLinkChannel(std::shared_ptr<yacl::link::Context> ctx, size_t peer_rank)
      : ctx_(std::move(ctx)), peer_rank_(peer_rank) {}

  void send(std::unique_ptr<SenderOperation> sop) override {
    SendPayload("request", request_send_count_, [&](StreamChannel& channel) {
      channel.send(std::move(sop));
    });
  }

  std::unique_ptr<SenderOperation> receive_operation(
      std::shared_ptr<seal::SEALContext> context,
      SenderOperationType expected = SenderOperationType::sop_unknown) override {
    return ReceivePayload<std::unique_ptr<SenderOperation>>(
        "request", request_recv_count_, [&](StreamChannel& channel) {
          return channel.receive_operation(std::move(context), expected);
        });
  }

  void send(std::unique_ptr<SenderOperationResponse> sop_response) override {
    SendPayload("response", response_send_count_, [&](StreamChannel& channel) {
      channel.send(std::move(sop_response));
    });
  }

  std::unique_ptr<SenderOperationResponse> receive_response(
      SenderOperationType expected = SenderOperationType::sop_unknown) override {
    return ReceivePayload<std::unique_ptr<SenderOperationResponse>>(
        "response", response_recv_count_, [&](StreamChannel& channel) {
          return channel.receive_response(expected);
        });
  }

  void send(std::unique_ptr<ResultPackage> rp) override {
    SendPayload("result", result_send_count_, [&](StreamChannel& channel) {
      channel.send(std::move(rp));
    });
  }

  std::unique_ptr<ResultPackage> receive_result(
      std::shared_ptr<seal::SEALContext> context) override {
    return ReceivePayload<std::unique_ptr<ResultPackage>>(
        "result", result_recv_count_, [&](StreamChannel& channel) {
          return channel.receive_result(std::move(context));
        });
  }

 private:
  template <typename Fn>
  void SendPayload(std::string_view kind, uint64_t& counter, Fn&& fn) {
    std::lock_guard<std::mutex> lock(send_mu_);
    const uint64_t current = counter++;
    std::stringstream stream;
    StreamChannel channel(stream);
    fn(channel);

    const std::string payload = stream.str();
    bytes_sent_.fetch_add(payload.size(), std::memory_order_relaxed);
    ctx_->Send(peer_rank_,
               yacl::ByteContainerView(payload.data(), payload.size()),
               MakeTag(kind, current));
  }

  template <typename T, typename Fn>
  T ReceivePayload(std::string_view kind, uint64_t& counter, Fn&& fn) {
    auto buffer = ctx_->Recv(peer_rank_, MakeTag(kind, counter++));
    bytes_received_.fetch_add(buffer.size(), std::memory_order_relaxed);

    std::stringstream stream(std::string(buffer.data<char>(), buffer.size()));
    StreamChannel channel(stream);
    return fn(channel);
  }

  std::string MakeTag(std::string_view kind, uint64_t counter) const {
    return "apsi_" + std::string(kind) + "_" + std::to_string(counter);
  }

  std::shared_ptr<yacl::link::Context> ctx_;
  size_t peer_rank_;
  std::mutex send_mu_;
  uint64_t request_send_count_ = 0;
  uint64_t request_recv_count_ = 0;
  uint64_t response_send_count_ = 0;
  uint64_t response_recv_count_ = 0;
  uint64_t result_send_count_ = 0;
  uint64_t result_recv_count_ = 0;
};

}  // namespace apsi::network
