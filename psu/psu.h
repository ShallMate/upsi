#pragma once

#include <memory>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/context.h"
#include "yacl/secparam.h"

/* security parameter declaration */
YACL_MODULE_DECLARE("psu", SecParam::C::k128, SecParam::S::k40);

uint64_t Evaluate(const std::vector<uint64_t>& coeffs, uint64_t x);

std::vector<uint64_t> Interpolate(const std::vector<uint64_t>& xs,
                                  const std::vector<uint64_t>& ys);

// Scalable Private Set Union from Symmetric-Key Techniques
// https://eprint.iacr.org/2019/776.pdf (Figure 10)

std::vector<uint128_t> KrtwPsuSend(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes);

std::vector<uint128_t> KrtwPsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx,
    const std::vector<uint128_t>& elem_hashes);
