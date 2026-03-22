#include "examples/upsi/psu/iblt_based_psu/iblt_h5.hpp"

#include <cmath>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

constexpr uint64_t kSeedConst0 = 0x9e3779b97f4a7c15ULL;
constexpr uint64_t kSeedConst1 = 0xbf58476d1ce4e5b9ULL;
constexpr uint64_t kSeedConst2 = 0x94d049bb133111ebULL;
constexpr uint64_t kOffsets[iblt_5h::NUM_HASH_FUNCS] = {
    0x243f6a8885a308d3ULL,
    0x13198a2e03707344ULL,
    0xa4093822299f31d0ULL,
    0x082efa98ec4e6c89ULL,
    0x452821e638d01377ULL,
};

inline uint64_t SplitMix64(uint64_t x) {
  x += 0x9e3779b97f4a7c15ULL;
  x = (x ^ (x >> 30)) * 0xbf58476d1ce4e5b9ULL;
  x = (x ^ (x >> 27)) * 0x94d049bb133111ebULL;
  return x ^ (x >> 31);
}

inline uint64_t ItemHashWord(const iblt_5h::Item& item, uint64_t tweak) {
  const auto words = item.get<uint64_t>();
  return SplitMix64(words[0] ^ tweak) ^ SplitMix64(words[1] + tweak);
}

}  // namespace

iblt_5h::iblt_5h(osuCrypto::block seed, size_t threshold, double mult_fac)
    : hash_seed(seed),
      threshold(threshold),
      mult_fac(mult_fac),
      tab_len(calc_tab_len(threshold, mult_fac)),
      cnt(nullptr),
      sum(nullptr),
      seedsum(nullptr),
      cnt_vec(nullptr),
      sum_vec(nullptr) {
  cnt_storage_.assign(tab_len, 0);
  sum_storage_.assign(tab_len, osuCrypto::ZeroBlock);
  seedsum_storage_.assign(tab_len, osuCrypto::ZeroBlock);

  cnt = cnt_storage_.data();
  sum = sum_storage_.data();
  seedsum = seedsum_storage_.data();
  cnt_vec = &cnt_storage_;
  sum_vec = &sum_storage_;
}

size_t iblt_5h::calc_tab_len(size_t threshold, double mult_fac) {
  if (threshold == 0) {
    threshold = 1;
  }
  if (!std::isfinite(mult_fac) || mult_fac < 1.0) {
    mult_fac = 1.0;
  }

  const long double scaled =
      static_cast<long double>(threshold) * static_cast<long double>(mult_fac);
  if (scaled >= static_cast<long double>(std::numeric_limits<size_t>::max())) {
    return std::numeric_limits<size_t>::max();
  }

  size_t len = static_cast<size_t>(std::ceil(scaled));
  if (len < NUM_HASH_FUNCS) {
    len = NUM_HASH_FUNCS;
  }
  return len;
}

void iblt_5h::hash_eval(const Item& item, size_t out_idxs[NUM_HASH_FUNCS]) const {
  const auto seeds = hash_seed.get<uint64_t>();
  uint64_t h1 = ItemHashWord(item, seeds[0] ^ kSeedConst0);
  uint64_t h2 = ItemHashWord(item, seeds[1] ^ kSeedConst1);
  h2 |= 1ULL;

  for (size_t i = 0; i < NUM_HASH_FUNCS; ++i) {
    uint64_t probe = h1 + i * h2 + kOffsets[i];
    size_t idx = static_cast<size_t>(probe % tab_len);

    // Keep per-element hash outputs distinct for stable peeling behavior.
    for (size_t j = 0; j < i; ++j) {
      if (out_idxs[j] == idx) {
        probe = SplitMix64(probe + kSeedConst2 + j);
        idx = static_cast<size_t>(probe % tab_len);
        j = static_cast<size_t>(-1);
      }
    }

    out_idxs[i] = idx;
  }
}

void iblt_5h::add_item(const Item& item, const osuCrypto::block& seed,
                       bool with_seed) {
  size_t idxs[NUM_HASH_FUNCS];
  hash_eval(item, idxs);

  for (size_t i = 0; i < NUM_HASH_FUNCS; ++i) {
    const size_t idx = idxs[i];
    cnt_storage_[idx] += 1;
    sum_storage_[idx] ^= item;
    if (with_seed) {
      seedsum_storage_[idx] = seedsum_storage_[idx] ^ seed;
    }
  }
}

void iblt_5h::remove_item(const Item& item, const osuCrypto::block& seed,
                          bool with_seed) {
  size_t idxs[NUM_HASH_FUNCS];
  hash_eval(item, idxs);

  for (size_t i = 0; i < NUM_HASH_FUNCS; ++i) {
    const size_t idx = idxs[i];
    if (cnt_storage_[idx] > 0) {
      cnt_storage_[idx] -= 1;
    }
    sum_storage_[idx] ^= item;
    if (with_seed) {
      seedsum_storage_[idx] = seedsum_storage_[idx] ^ seed;
    }
  }
}

void iblt_5h::add(const std::vector<Item>& items) {
  for (const auto& item : items) {
    add_item(item, osuCrypto::ZeroBlock, false);
  }
}

void iblt_5h::addKeys(const ankerl::unordered_dense::set<Item>& items) {
  for (const auto& item : items) {
    add_item(item, osuCrypto::ZeroBlock, false);
  }
}

void iblt_5h::add(const ankerl::unordered_dense::set<Item>& items,
                  std::span<osuCrypto::block> seeds) {
  if (items.size() != seeds.size()) {
    throw std::invalid_argument("iblt_5h::add items/seeds size mismatch");
  }

  size_t i = 0;
  for (const auto& item : items) {
    add_item(item, seeds[i], true);
    ++i;
  }
}

void iblt_5h::remove(const std::vector<Item>& items) {
  for (const auto& item : items) {
    remove_item(item, osuCrypto::ZeroBlock, false);
  }
}

void iblt_5h::removeKeys(const std::vector<Item>& items) { remove(items); }

void iblt_5h::remove(const std::vector<Item>& items,
                     const std::vector<osuCrypto::block>& seeds) {
  if (items.size() != seeds.size()) {
    throw std::invalid_argument("iblt_5h::remove items/seeds size mismatch");
  }

  for (size_t i = 0; i < items.size(); ++i) {
    remove_item(items[i], seeds[i], true);
  }
}

void iblt_5h::unique_hash_evals(
    const std::vector<Item>& peeled_items,
    osuCrypto::AlignedVector<size_t>& out_probe_idxs,
    const osuCrypto::BitVector& peeled_bm) const {
  out_probe_idxs.clear();
  if (peeled_items.empty() || tab_len == 0) {
    return;
  }

  // Set semantics for Q: de-duplicate repeated probe bins within the round.
  out_probe_idxs.reserve(std::min(peeled_items.size() * NUM_HASH_FUNCS, tab_len));
  std::vector<uint8_t> selected(tab_len, 0);

  for (const auto& item : peeled_items) {
    size_t idxs[NUM_HASH_FUNCS];
    hash_eval(item, idxs);
    for (size_t i = 0; i < NUM_HASH_FUNCS; ++i) {
      const size_t idx = idxs[i];
      if (peeled_bm.size() == tab_len && static_cast<bool>(peeled_bm[idx])) {
        continue;
      }
      if (!selected[idx]) {
        selected[idx] = 1;
        out_probe_idxs.push_back(idx);
      }
    }
  }
}
