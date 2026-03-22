#pragma once

#include <functional>
#include <memory>
#include <unordered_set>

// The upstream IBLT-based-PSU code uses ankerl::unordered_dense::set.
// Provide a local alias so this example can build without that third-party
// header being installed system-wide.
namespace ankerl::unordered_dense {

template <typename Key, typename Hash = std::hash<Key>,
          typename KeyEqual = std::equal_to<Key>,
          typename Allocator = std::allocator<Key>>
using set = std::unordered_set<Key, Hash, KeyEqual, Allocator>;

}  // namespace ankerl::unordered_dense
