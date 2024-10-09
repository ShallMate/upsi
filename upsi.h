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