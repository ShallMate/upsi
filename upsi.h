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

#include "examples/upsi/ecdhpsi/receiver.h"
#include "examples/upsi/ecdhpsi/sender.h"
#include "examples/upsi/rr22/okvs/baxos.h"

#include "yacl/base/int128.h"
#include "yacl/link/context.h"

std::vector<uint128_t> BasePsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& x,
    okvs::Baxos baxos);

std::vector<uint128_t> BasePsiSend(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& y,
    okvs::Baxos baxos);

std::vector<uint128_t> UPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& x,
                                std::vector<uint128_t>& xadd,
                                std::vector<uint128_t>& xsub,
                                EcdhReceiver& xaddreceiver,
                                EcdhSender& yaddsender,
                                std::set<uint128_t> intersection_receiver);

std::vector<uint128_t> UPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& y,
                                std::vector<uint128_t>& yadd,
                                std::vector<uint128_t>& ysub,
                                EcdhReceiver& yaddreceiver,
                                EcdhSender& xaddsender,
                                std::set<uint128_t> intersection_sender);