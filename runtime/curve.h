#pragma once
#include "runtime/types.h"
#include <cryptoTools/Crypto/SodiumCurve.h>
namespace upsi_runtime::crypto {
using EcPoint = osuCrypto::Sodium::Rist25519;
using Scalar = osuCrypto::Sodium::Prime25519;
inline Scalar RandomScalar() {
  osuCrypto::PRNG prng(osuCrypto::sysRandomSeed());
  Scalar s(prng); while(s.iszero()) s.randomize(prng); return s;
}
class EcGroup {
 public:
  EcPoint HashToCurve(std::string_view s) const {
    osuCrypto::RandomOracle ro(EcPoint::fromHashLength); ro.Update(s.data(),s.size());
    return EcPoint::fromHash(ro);
  }
  EcPoint Mul(const EcPoint& p,const Scalar& s) const { return p*s; }
  void MulInplace(EcPoint* p,const Scalar& s) const { *p *= s; }
  size_t GetSerializeLength() const { return 32; }
  void SerializePoint(const EcPoint& p,uint8_t* out,size_t n) const { UPSI_ENFORCE(n==32); p.toBytes(out); }
  std::string SerializePoint(const EcPoint& p) const { return std::string(reinterpret_cast<const char*>(p.data),32); }
  EcPoint DeserializePoint(std::span<const uint8_t> in) const {
    UPSI_ENFORCE(in.size()==32); UPSI_ENFORCE(crypto_core_ristretto255_is_valid_point(in.data()));
    EcPoint p; p.fromBytes(in.data()); return p;
  }
};
}
