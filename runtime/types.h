#pragma once
#include <omp.h>
#include <algorithm>
#include <array>
#include <atomic>
#include <cmath>
#include <cstring>
#include <future>
#include <memory>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>
#include <cryptoTools/Common/Defines.h>
#include <cryptoTools/Crypto/PRNG.h>
#include <cryptoTools/Crypto/RandomOracle.h>

using uint128_t = unsigned __int128;
#define UPSI_ENFORCE(condition, ...) do { if (!(condition)) throw std::runtime_error("UPSI check failed: " #condition); } while (false)
#define UPSI_THROW(message, ...) throw std::runtime_error(message)
namespace upsi_runtime {
template<class T> using Span = std::span<T>;
template<class T> auto MakeSpan(T* p, size_t n) { return std::span<T>(p,n); }
template<class C> auto MakeSpan(C& c) { return std::span(c); }
using string_view = std::string_view;
inline uint128_t MakeUint128(uint64_t hi, uint64_t lo) { return (uint128_t(hi)<<64)|lo; }
inline std::pair<uint64_t,uint64_t> DecomposeUInt128(uint128_t x) { return {uint64_t(x>>64),uint64_t(x)}; }
inline osuCrypto::block ToBlock(uint128_t x) { return osuCrypto::block(uint64_t(x>>64),uint64_t(x)); }
inline uint128_t FromBlock(const osuCrypto::block& b) { auto w=b.get<uint64_t>(); return MakeUint128(w[1],w[0]); }
class ByteContainerView {
 public:
  ByteContainerView(const void* p, size_t n): p_(static_cast<const uint8_t*>(p)), n_(n) {}
  ByteContainerView(const std::string& s): ByteContainerView(s.data(),s.size()) {}
  ByteContainerView(std::string_view s): ByteContainerView(s.data(),s.size()) {}
  template<class T> ByteContainerView(const std::vector<T>& v): ByteContainerView(v.data(),v.size()*sizeof(T)) {}
  const uint8_t* data() const { return p_; } size_t size() const { return n_; }
 private: const uint8_t* p_; size_t n_;
};
class Buffer {
 public:
  explicit Buffer(std::vector<uint8_t> b): bytes_(std::move(b)) {}
  template<class T=void> T* data() { return reinterpret_cast<T*>(bytes_.data()); }
  template<class T=void> const T* data() const { return reinterpret_cast<const T*>(bytes_.data()); }
  size_t size() const { return bytes_.size(); }
 private: std::vector<uint8_t> bytes_;
};
inline std::string SerializeUint128(uint128_t x) {
  std::string s(16,'\0'); for(size_t i=0;i<16;++i) s[i]=char(x>>(8*i)); return s;
}
inline uint128_t DeserializeUint128(const Buffer& b) {
  UPSI_ENFORCE(b.size()==16); uint128_t x=0;
  for(size_t i=0;i<16;++i) x|=uint128_t(b.data<uint8_t>()[i])<<(8*i); return x;
}
inline std::atomic<size_t> parallel_threads{2};
template<class Fn> void parallel_for(size_t begin,size_t end,Fn fn) {
  // OpenMP follows the caller's configured thread count.
  #pragma omp parallel num_threads(parallel_threads.load())
  {
    const size_t count=static_cast<size_t>(omp_get_num_threads());
    const size_t rank=static_cast<size_t>(omp_get_thread_num());
    fn(begin+(end-begin)*rank/count,begin+(end-begin)*(rank+1)/count);
  }
}
namespace crypto {
inline uint128_t Hash128(ByteContainerView v) {
  osuCrypto::RandomOracle h(16); h.Update(v.data(),v.size());
  osuCrypto::block out; h.Final(out); return FromBlock(out);
}
inline uint128_t FastRandU128() { return FromBlock(osuCrypto::sysRandomSeed()); }
inline uint64_t FastRandU64() { return uint64_t(FastRandU128()); }
template<class T> class Prg {
 public:
  explicit Prg(uint128_t seed): impl(ToBlock(seed)) {}
  template<class U> void Fill(std::span<U> out) { impl.get(reinterpret_cast<uint8_t*>(out.data()),out.size_bytes()); }
  osuCrypto::PRNG impl;
};
}
}
