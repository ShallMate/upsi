#pragma once
#include "runtime/link.h"
#include <libOTe/Vole/Silent/SilentVoleSender.h>
#include <libOTe/Vole/Silent/SilentVoleReceiver.h>
namespace upsi_runtime::crypto {
// libOTe's default code replaces the deprecated Silver code; correlation is c=a*delta+b.
inline void VoleReceive(link::Context& ctx,std::span<uint128_t> a,std::span<uint128_t> c) {
  osuCrypto::SilentVoleReceiver<osuCrypto::block> vole;
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
  decltype(vole)::VecG aa; decltype(vole)::VecF cc;
  aa.resize(a.size()); cc.resize(c.size());
  coproto::sync_wait(vole.silentReceive(aa,cc,prng,ctx.socket()));
  for(size_t i=0;i<a.size();++i) { a[i]=FromBlock(aa[i]); c[i]=FromBlock(cc[i]); }
}
inline uint128_t VoleSend(link::Context& ctx,std::span<uint128_t> b) {
  osuCrypto::SilentVoleSender<osuCrypto::block> vole;
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed()); auto delta=prng.get<osuCrypto::block>();
  decltype(vole)::VecF bb; bb.resize(b.size());
  coproto::sync_wait(vole.silentSend(delta,bb,prng,ctx.socket()));
  for(size_t i=0;i<b.size();++i) b[i]=FromBlock(bb[i]); return FromBlock(delta);
}
inline uint128_t GfMul128(uint128_t a,uint128_t b) { return FromBlock(ToBlock(a).gf128Mul(ToBlock(b))); }
}
