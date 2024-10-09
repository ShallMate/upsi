#pragma once

#include "examples/upsi/rr22/okvs/baxos.h"

#include "yacl/link/test_util.h"

namespace rr22 {

std::vector<uint128_t> RR22PsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos);

std::vector<uint128_t> RR22PsiSend(
    const std::shared_ptr<yacl::link::Context>& ctx,
    std::vector<uint128_t>& elem_hashes, okvs::Baxos baxos);

}  // namespace rr22
