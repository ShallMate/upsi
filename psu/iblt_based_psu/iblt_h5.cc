#include "examples/upsi/psu/iblt_based_psu/iblt_h5.hpp"

#include <algorithm>
#include <cmath>
#include <limits>
#include <stdexcept>
#include <vector>

namespace {

constexpr uint64_t kHashTweakHi = 11400095595373522076ULL;
constexpr uint64_t kHashTweakLo = 0x9e3779b97f4a7c15ULL;

osuCrypto::block HashTweakBlock() {
  return osuCrypto::block(kHashTweakHi, kHashTweakLo);
}

}  // namespace

iblt_5h::iblt_5h(osuCrypto::block seed, size_t threshold, double mult_fac)
    : hash_seed(seed),
      threshold(threshold),
      mult_fac(mult_fac),
      tab_len(calc_tab_len(threshold, mult_fac)),
      subtab_len(calc_subtab_len(threshold, mult_fac)),
      cnt(nullptr),
      sum(nullptr),
      seedsum(nullptr),
      cnt_vec(nullptr),
      sum_vec(nullptr) {
  aes_.setKey(hash_seed);

  cnt_storage_.assign(tab_len, 0);
  sum_storage_.assign(tab_len, osuCrypto::ZeroBlock);
  seedsum_storage_.assign(tab_len, osuCrypto::ZeroBlock);
  unique_hash_evals_bitmap_.assign(tab_len, 0);

  cnt = cnt_storage_.data();
  sum = sum_storage_.data();
  seedsum = seedsum_storage_.data();
  cnt_vec = &cnt_storage_;
  sum_vec = &sum_storage_;
}

size_t iblt_5h::calc_subtab_len(size_t threshold, double mult_fac) {
  if (threshold == 0) {
    threshold = 1;
  }
  if (!std::isfinite(mult_fac) || mult_fac < 1.0) {
    mult_fac = 1.0;
  }

  const long double scaled =
      static_cast<long double>(threshold) * static_cast<long double>(mult_fac) /
      static_cast<long double>(NUM_HASH_FUNCS);
  if (scaled >= static_cast<long double>(std::numeric_limits<size_t>::max() /
                                         NUM_HASH_FUNCS)) {
    return std::numeric_limits<size_t>::max() / NUM_HASH_FUNCS;
  }

  size_t len = static_cast<size_t>(std::ceil(scaled));
  return std::max<size_t>(len, 1);
}

size_t iblt_5h::calc_tab_len(size_t threshold, double mult_fac) {
  return NUM_HASH_FUNCS * calc_subtab_len(threshold, mult_fac);
}

void iblt_5h::hash_items(std::span<const Item> items,
                         std::vector<osuCrypto::block>& out_hashes) const {
  out_hashes.resize(items.size() * 2);
  if (items.empty()) {
    return;
  }

  std::vector<osuCrypto::block> in_blocks(items.size() * 2);
  const auto tweak = HashTweakBlock();
  for (size_t i = 0; i < items.size(); ++i) {
    in_blocks[2 * i] = items[i];
    in_blocks[2 * i + 1] = items[i] ^ tweak;
  }

  aes_.hashBlocks(in_blocks.data(), in_blocks.size(), out_hashes.data());
}

size_t iblt_5h::table_idx(const std::vector<osuCrypto::block>& hash_blocks,
                          size_t item_idx, size_t hash_idx) const {
  const auto word_idx = hash_idx < 4 ? hash_idx : 4;
  const auto hash_words =
      hash_blocks[2 * item_idx + (hash_idx / 4)].get<uint32_t>();
  return (static_cast<size_t>(hash_words[word_idx % 4]) % subtab_len) +
         hash_idx * subtab_len;
}

void iblt_5h::hash_eval(const Item& item, size_t out_idxs[NUM_HASH_FUNCS]) const {
  const Item items[1] = {item};
  std::vector<osuCrypto::block> hash_blocks;
  hash_items(std::span<const Item>(items, 1), hash_blocks);

  for (size_t i = 0; i < NUM_HASH_FUNCS; ++i) {
    out_idxs[i] = table_idx(hash_blocks, 0, i);
  }
}

void iblt_5h::add_items(std::span<const Item> items,
                        std::span<const osuCrypto::block> seeds,
                        bool with_seed) {
  if (with_seed && items.size() != seeds.size()) {
    throw std::invalid_argument("iblt_5h::add items/seeds size mismatch");
  }

  std::vector<osuCrypto::block> hash_blocks;
  hash_items(items, hash_blocks);

  for (size_t i = 0; i < items.size(); ++i) {
    for (size_t j = 0; j < NUM_HASH_FUNCS; ++j) {
      const size_t idx = table_idx(hash_blocks, i, j);
      cnt_storage_[idx] += 1;
      sum_storage_[idx] ^= items[i];
      if (with_seed) {
        seedsum_storage_[idx] = seedsum_storage_[idx] ^ seeds[i];
      }
    }
  }
}

void iblt_5h::remove_items(std::span<const Item> items,
                           std::span<const osuCrypto::block> seeds,
                           bool with_seed) {
  if (with_seed && items.size() != seeds.size()) {
    throw std::invalid_argument("iblt_5h::remove items/seeds size mismatch");
  }

  std::vector<osuCrypto::block> hash_blocks;
  hash_items(items, hash_blocks);

  for (size_t i = 0; i < items.size(); ++i) {
    for (size_t j = 0; j < NUM_HASH_FUNCS; ++j) {
      const size_t idx = table_idx(hash_blocks, i, j);
      if (cnt_storage_[idx] > 0) {
        cnt_storage_[idx] -= 1;
      }
      sum_storage_[idx] ^= items[i];
      if (with_seed) {
        seedsum_storage_[idx] = seedsum_storage_[idx] ^ seeds[i];
      }
    }
  }
}

void iblt_5h::add_item(const Item& item, const osuCrypto::block& seed,
                       bool with_seed) {
  add_items(std::span<const Item>(&item, 1),
            std::span<const osuCrypto::block>(&seed, with_seed ? 1 : 0),
            with_seed);
}

void iblt_5h::remove_item(const Item& item, const osuCrypto::block& seed,
                          bool with_seed) {
  remove_items(std::span<const Item>(&item, 1),
               std::span<const osuCrypto::block>(&seed, with_seed ? 1 : 0),
               with_seed);
}

void iblt_5h::add(const std::vector<Item>& items) {
  add_items(std::span<const Item>(items.data(), items.size()), {}, false);
}

void iblt_5h::addKeys(const ankerl::unordered_dense::set<Item>& items) {
  std::vector<Item> items_vec(items.begin(), items.end());
  add(items_vec);
}

void iblt_5h::add(const ankerl::unordered_dense::set<Item>& items,
                  std::span<osuCrypto::block> seeds) {
  std::vector<Item> items_vec(items.begin(), items.end());
  add_items(std::span<const Item>(items_vec.data(), items_vec.size()), seeds,
            true);
}

void iblt_5h::remove(const std::vector<Item>& items) {
  remove_items(std::span<const Item>(items.data(), items.size()), {}, false);
}

void iblt_5h::removeKeys(const std::vector<Item>& items) { remove(items); }

void iblt_5h::remove(const std::vector<Item>& items,
                     const std::vector<osuCrypto::block>& seeds) {
  remove_items(std::span<const Item>(items.data(), items.size()),
               std::span<const osuCrypto::block>(seeds.data(), seeds.size()),
               true);
}

void iblt_5h::unique_hash_evals(
    const std::vector<Item>& peeled_items,
    osuCrypto::AlignedVector<size_t>& out_probe_idxs,
    const osuCrypto::BitVector& peeled_bm) const {
  out_probe_idxs.clear();
  if (peeled_items.empty() || tab_len == 0) {
    return;
  }

  out_probe_idxs.reserve(std::min(peeled_items.size() * NUM_HASH_FUNCS, tab_len));
  std::fill(unique_hash_evals_bitmap_.begin(), unique_hash_evals_bitmap_.end(),
            0);

  std::vector<osuCrypto::block> hash_blocks;
  hash_items(std::span<const Item>(peeled_items.data(), peeled_items.size()),
             hash_blocks);

  for (size_t i = 0; i < peeled_items.size(); ++i) {
    for (size_t j = 0; j < NUM_HASH_FUNCS; ++j) {
      const size_t idx = table_idx(hash_blocks, i, j);
      if (peeled_bm.size() == tab_len && static_cast<bool>(peeled_bm[idx])) {
        continue;
      }
      if (!unique_hash_evals_bitmap_[idx]) {
        unique_hash_evals_bitmap_[idx] = 1;
        out_probe_idxs.push_back(idx);
      }
    }
  }
}
