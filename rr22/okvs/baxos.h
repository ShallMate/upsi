#pragma once
#include "runtime/types.h"
#include "volePSI/Paxos.h"
namespace okvs {
using PaxosParam = volePSI::PaxosParam;
class Baxos {
 public:
  void Init(size_t n,size_t bin,size_t weight,size_t ssp,PaxosParam::DenseType dt,uint128_t seed) { impl_.init(n,bin,weight,ssp,dt,upsi_runtime::ToBlock(seed)); }
  size_t size() { return impl_.size(); }
  void Solve(std::span<const uint128_t> keys,std::span<const uint128_t> vals,std::span<uint128_t> out,std::nullptr_t,size_t threads) {
    auto k=Blocks(keys),v=Blocks(vals); std::vector<osuCrypto::block> o(out.size());
    impl_.solve<osuCrypto::block>(k,v,o,nullptr,threads); Copy(o,out);
  }
  void Decode(std::span<const uint128_t> keys,std::span<uint128_t> vals,std::span<const uint128_t> encoded,size_t threads) {
    auto k=Blocks(keys),p=Blocks(encoded); std::vector<osuCrypto::block> v(vals.size());
    impl_.decode<osuCrypto::block>(k,v,p,threads); Copy(v,vals);
  }
 private:
  static std::vector<osuCrypto::block> Blocks(std::span<const uint128_t> in) { std::vector<osuCrypto::block> out; out.reserve(in.size()); for(auto x:in) out.push_back(upsi_runtime::ToBlock(x)); return out; }
  static void Copy(const std::vector<osuCrypto::block>& in,std::span<uint128_t> out) { for(size_t i=0;i<in.size();++i) out[i]=upsi_runtime::FromBlock(in[i]); }
  volePSI::Baxos impl_;
};
}
