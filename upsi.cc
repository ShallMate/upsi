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

#include "examples/upsi/upsi.h"

#include <cstdint>
#include <future>
#include <vector>

#include "examples/upsi/ecdhpsi/receiver.h"
#include "examples/upsi/ecdhpsi/sender.h"
#include "examples/upsi/psu/psu.h"
#include "examples/upsi/rr22/okvs/baxos.h"
#include "examples/upsi/rr22/rr22.h"

using namespace std;

std::vector<uint128_t> BasePsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& x,
    okvs::Baxos baxos) {
  return rr22::RR22PsiRecv(ctx, x, baxos);
}

std::vector<uint128_t> BasePsiSend(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& y,
    okvs::Baxos baxos) {
  return rr22::RR22PsiSend(ctx, y, baxos);
}

std::vector<uint128_t> UPsiRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& x,
                                std::vector<uint128_t>& xadd,
                                std::vector<uint128_t>& xsub,
                                EcdhReceiver& xaddreceiver,
                                EcdhSender& yaddsender,
                                std::set<uint128_t> intersection_receiver) {
  yaddsender.UpdatePRFs(absl::MakeSpan(xadd));
  yaddsender.DeletePRFs(absl::MakeSpan(xsub));
  // cout << ctx->GetStats()->recv_bytes << endl;
  // cout << ctx->GetStats()->sent_bytes << endl;
  uint32_t xadd_size = xadd.size();
  std::vector<uint8_t> size_data(
      reinterpret_cast<uint8_t*>(&xadd_size),
      reinterpret_cast<uint8_t*>(&xadd_size) + sizeof(xadd_size));
  ctx->SendAsync(ctx->NextRank(), size_data, "xadd_size");
  yacl::Buffer size_data_yadd = ctx->Recv(ctx->PrevRank(), "yadd size");
  uint32_t yadd_size = *reinterpret_cast<uint32_t*>(size_data_yadd.data());
  // cout << "yadd_size = " << yadd_size << endl;
  yaddsender.EcdhPsiSend(ctx, yadd_size);
  std::vector<uint128_t> t = xaddreceiver.EcdhPsiRecv(ctx, xadd);
  //cout << "t=" << t.size() << endl;

  std::vector<uint128_t> u = KrtwPsuSend(ctx, t);
  //cout << "u=" << u.size() << endl;

  std::set<uint128_t> xsubset(xsub.begin(), xsub.end());
  std::set<uint128_t> xsubsetintersction;
  std::set_intersection(
      xsubset.begin(), xsubset.end(), intersection_receiver.begin(),
      intersection_receiver.end(),
      std::inserter(xsubsetintersction, xsubsetintersction.begin()));
  std::vector<uint128_t> xsubintersction(xsubsetintersction.begin(),
                                         xsubsetintersction.end());

  std::vector<uint128_t> w = KrtwPsuSend(ctx, xsubintersction);
  //cout << "w=" << w.size() << endl;
  std::set<uint128_t> wset(w.begin(), w.end());

  // 求 I \ W (差集)
  std::set<uint128_t> diff;
  std::set_difference(intersection_receiver.begin(),
                      intersection_receiver.end(), wset.begin(), wset.end(),
                      std::inserter(diff, diff.begin()));
  std::set<uint128_t> result;
  std::set_union(diff.begin(), diff.end(), u.begin(), u.end(),
                 std::inserter(result, result.begin()));
  std::vector<uint128_t> psi_result(result.begin(), result.end());
  return psi_result;
}

std::vector<uint128_t> UPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& y,
                                std::vector<uint128_t>& yadd,
                                std::vector<uint128_t>& ysub,
                                EcdhReceiver& yaddreceiver,
                                EcdhSender& xaddsender,
                                std::set<uint128_t> intersection_sender) {
  xaddsender.UpdatePRFs(absl::MakeSpan(yadd));
  xaddsender.DeletePRFs(absl::MakeSpan(ysub));
  uint32_t yadd_size = yadd.size();
  std::vector<uint8_t> size_data(
      reinterpret_cast<uint8_t*>(&yadd_size),
      reinterpret_cast<uint8_t*>(&yadd_size) + sizeof(yadd_size));
  ctx->SendAsync(ctx->NextRank(), size_data, "yadd_size");
  yacl::Buffer size_data_xadd = ctx->Recv(ctx->PrevRank(), "xadd size");
  uint32_t xadd_size = *reinterpret_cast<uint32_t*>(size_data_xadd.data());
  std::vector<uint128_t> v = yaddreceiver.EcdhPsiRecv(ctx, yadd);
  //cout << "v = " << v.size() << endl;

  xaddsender.EcdhPsiSend(ctx, xadd_size);
  std::vector<uint128_t> u = KrtwPsuRecv(ctx, v);
  //cout << "u = " << u.size() << endl;

  std::set<uint128_t> ysubset(ysub.begin(), ysub.end());
  std::set<uint128_t> ysubsetintersction;
  std::set_intersection(
      ysubset.begin(), ysubset.end(), intersection_sender.begin(),
      intersection_sender.end(),
      std::inserter(ysubsetintersction, ysubsetintersction.begin()));
  std::vector<uint128_t> ysubintersction(ysubsetintersction.begin(),
                                         ysubsetintersction.end());
  // cout << ysubintersction.size() << endl;
  std::vector<uint128_t> w = KrtwPsuRecv(ctx, ysubintersction);
  //cout<<w.size()<<endl;
  std::set<uint128_t> wset(w.begin(), w.end());
  // 求 I \ W (差集)
  std::set<uint128_t> diff;
  std::set_difference(intersection_sender.begin(), intersection_sender.end(),
                      wset.begin(), wset.end(),
                      std::inserter(diff, diff.begin()));
  std::set<uint128_t> result;
  std::set_union(diff.begin(), diff.end(), u.begin(), u.end(),
                 std::inserter(result, result.begin()));
  std::vector<uint128_t> psi_result(result.begin(), result.end());
  return psi_result;
}