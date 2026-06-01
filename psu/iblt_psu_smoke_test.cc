#include "examples/upsi/psu/psu.h"

#include <algorithm>
#include <future>
#include <iostream>
#include <set>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/link/test_util.h"

namespace {

std::vector<uint128_t> MakeItems(size_t begin, size_t size) {
  std::vector<uint128_t> items;
  items.reserve(size);
  for (size_t i = 0; i < size; ++i) {
    const uint64_t value = static_cast<uint64_t>(begin + i);
    items.push_back(yacl::MakeUint128(value ^ 0x9e3779b97f4a7c15ULL, value));
  }
  return items;
}

std::vector<uint128_t> SortedUnion(const std::vector<uint128_t>& lhs,
                                   const std::vector<uint128_t>& rhs) {
  std::set<uint128_t> union_set(lhs.begin(), lhs.end());
  union_set.insert(rhs.begin(), rhs.end());
  return {union_set.begin(), union_set.end()};
}

}  // namespace

int main() {
  constexpr size_t kSetSize = 128;
  auto contexts = yacl::link::test::SetupWorld(2);
  SetDefaultPsuProtocol(PsuProtocol::kIblt);

  auto sender_items = MakeItems(0, kSetSize);
  auto receiver_items = MakeItems(kSetSize / 2, kSetSize);
  auto expected = SortedUnion(sender_items, receiver_items);

  auto sender = std::async(std::launch::async, [&] {
    return PsuSend(contexts[0], sender_items);
  });
  auto receiver = std::async(std::launch::async, [&] {
    return PsuRecv(contexts[1], receiver_items);
  });

  auto sender_union = sender.get();
  auto receiver_union = receiver.get();
  std::sort(sender_union.begin(), sender_union.end());
  std::sort(receiver_union.begin(), receiver_union.end());

  if (sender_union != expected || receiver_union != expected) {
    std::cerr << "IBLT PSU smoke failed: expected union size " << expected.size()
              << ", sender got " << sender_union.size() << ", receiver got "
              << receiver_union.size() << std::endl;
    return 1;
  }

  return 0;
}
