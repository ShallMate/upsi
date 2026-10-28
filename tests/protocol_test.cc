#include "aPSI.h"
#include "psu/psu.h"
#include "psu/krtw19_psu.h"
#include "rr22/rr22.h"
#include "runtime/curve.h"
#include <filesystem>
#include <iostream>

using namespace upsi_runtime;
std::vector<uint128_t> Items(size_t begin,size_t n) {
  std::vector<uint128_t> out;
  for(size_t i=begin;i<begin+n;++i) out.push_back(crypto::Hash128(std::to_string(i)));
  return out;
}
void CheckPsu(size_t nx,size_t ny) {
  auto ctx=link::SetupTcpWorld(2); auto x=Items(1,nx),y=Items(33,ny);
  std::set<uint128_t> expected(x.begin(),x.end()); expected.insert(y.begin(),y.end());
  auto sender=std::async(std::launch::async,[&]{return PsuSend(ctx[0],x);});
  auto receiver=std::async(std::launch::async,[&]{return PsuRecv(ctx[1],y);});
  auto a=sender.get(),b=receiver.get();
  UPSI_ENFORCE(std::set<uint128_t>(a.begin(),a.end())==expected);
  UPSI_ENFORCE(std::set<uint128_t>(b.begin(),b.end())==expected);
}
int main(int argc,char** argv) {
  omp_set_num_threads(2);
  const std::vector<uint64_t> xs{1,2,3,4},ys{8,7,6,5};
  auto coeffs=examples::psu::Interpolate(xs,ys);
  for(size_t i=0;i<xs.size();++i) UPSI_ENFORCE(examples::psu::Evaluate(coeffs,xs[i])==ys[i]);
  auto sk=crypto::RandomScalar(); crypto::EcGroup ec; auto p=ec.HashToCurve("UPSI-test");
  UPSI_ENFORCE(ec.SerializePoint(ec.Mul(ec.Mul(p,sk),sk.inverse()))==ec.SerializePoint(p));
  SetDefaultPsuProtocol(PsuProtocol::kKrtw);
  CheckPsu(64,96); CheckPsu(64,64); CheckPsu(0,0); CheckPsu(0,16);
  auto ctx=link::SetupTcpWorld(2); auto x=Items(0,128),y=Items(64,128);
  okvs::Baxos baxos; baxos.Init(128,128,3,40,okvs::PaxosParam::GF128,17);
  auto tx=std::async(std::launch::async,[&]{return rr22::RR22PsiSend(ctx[0],x,baxos);});
  auto rx=std::async(std::launch::async,[&]{return rr22::RR22PsiRecv(ctx[1],y,baxos);});
  auto a=tx.get(),b=rx.get(); auto e=Items(64,64); std::set<uint128_t> expected(e.begin(),e.end());
  UPSI_ENFORCE(std::set<uint128_t>(a.begin(),a.end())==expected);
  UPSI_ENFORCE(std::set<uint128_t>(b.begin(),b.end())==expected);
  apsi::ThreadPoolMgr::SetThreadCount(2);
  const auto param=std::filesystem::path(argv[0]).parent_path()/"parameters/256K-512.json";
  APSI db(param.string()); auto data=Items(0,128),query=Items(120,16); db.insertItems(data);
  auto answer=db.APsiRun(query); auto wanted=Items(120,8);
  UPSI_ENFORCE(std::set<uint128_t>(answer.begin(),answer.end())==std::set<uint128_t>(wanted.begin(),wanted.end()));
  auto removed=Items(120,4),added=Items(128,4); db.deleteItems(removed); db.insertItems(added);
  answer=db.APsiRun(query); wanted=Items(124,8);
  UPSI_ENFORCE(std::set<uint128_t>(answer.begin(),answer.end())==std::set<uint128_t>(wanted.begin(),wanted.end()));
  std::cout << "KRTW, RR22, curve and APSI 2.0 update checks passed\n";
}
