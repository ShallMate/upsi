#pragma once
#include "runtime/types.h"
namespace upsi_runtime {
// GF(2^64), polynomial x^64+x^4+x^3+x+1, matching the KRTW interpolation.
inline uint64_t GfMul64(uint64_t a,uint64_t b) {
  const osuCrypto::block modulus(0,0x1b);
  auto product=osuCrypto::block(0,a).clmulepi64_si128<0x00>(osuCrypto::block(0,b));
  auto fold=modulus.clmulepi64_si128<0x10>(product);
  auto reduced=product ^ fold ^ modulus.clmulepi64_si128<0x10>(fold);
  return reduced.get<uint64_t>()[0];
}
inline uint64_t GfInv64(uint64_t a) {
  UPSI_ENFORCE(a!=0); uint64_t r=a;
  for(unsigned i=1;i<63;++i) r=GfMul64(GfMul64(r,r),a);
  return GfMul64(r,r);
}
}
