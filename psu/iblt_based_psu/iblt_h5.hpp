#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

#include "cryptoTools/Common/BitVector.h"
#include "cryptoTools/Common/Defines.h"
#include "cryptoTools/Common/block.h"
#include "cryptoTools/Crypto/AES.h"
#include "examples/upsi/psu/iblt_based_psu/unordered_dense_compat.h"

class iblt_5h {
 public:
  static constexpr size_t NUM_HASH_FUNCS = 5;
  using Item = osuCrypto::block;

  iblt_5h(osuCrypto::block seed, size_t threshold, double mult_fac);
  ~iblt_5h() = default;

  iblt_5h(const iblt_5h&) = delete;
  iblt_5h& operator=(const iblt_5h&) = delete;

  static size_t calc_subtab_len(size_t threshold, double mult_fac);
  static size_t calc_tab_len(size_t threshold, double mult_fac);

  void hash_eval(const Item& item, size_t out_idxs[NUM_HASH_FUNCS]) const;

  void add(const std::vector<Item>& items);
  void addKeys(const ankerl::unordered_dense::set<Item>& items);
  void add(const ankerl::unordered_dense::set<Item>& items,
           std::span<osuCrypto::block> seeds);

  void remove(const std::vector<Item>& items);
  void removeKeys(const std::vector<Item>& items);
  void remove(const std::vector<Item>& items,
              const std::vector<osuCrypto::block>& seeds);

  void unique_hash_evals(const std::vector<Item>& peeled_items,
                         osuCrypto::AlignedVector<size_t>& out_probe_idxs,
                         const osuCrypto::BitVector& peeled_bm) const;

  osuCrypto::block hash_seed;
  size_t threshold;
  double mult_fac;
  size_t tab_len;
  size_t subtab_len;

  size_t* cnt;
  Item* sum;
  osuCrypto::block* seedsum;

  std::vector<size_t>* cnt_vec;
  std::vector<Item>* sum_vec;

 private:
  void hash_items(std::span<const Item> items,
                  std::vector<osuCrypto::block>& out_hashes) const;
  size_t table_idx(const std::vector<osuCrypto::block>& hash_blocks,
                   size_t item_idx, size_t hash_idx) const;
  void add_items(std::span<const Item> items,
                 std::span<const osuCrypto::block> seeds, bool with_seed);
  void remove_items(std::span<const Item> items,
                    std::span<const osuCrypto::block> seeds, bool with_seed);
  void add_item(const Item& item, const osuCrypto::block& seed,
                bool with_seed);
  void remove_item(const Item& item, const osuCrypto::block& seed,
                   bool with_seed);

  mutable osuCrypto::AES aes_;
  mutable std::vector<uint8_t> unique_hash_evals_bitmap_;
  std::vector<size_t> cnt_storage_;
  std::vector<Item> sum_storage_;
  std::vector<osuCrypto::block> seedsum_storage_;
};
