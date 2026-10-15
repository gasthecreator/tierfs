#include "locks.hpp"

#include <algorithm>
#include <limits>

namespace tierfs {

namespace {

constexpr uint64_t END = std::numeric_limits<uint64_t>::max();

uint64_t end_of(uint64_t start, uint64_t len) {
    if (len == 0) return END;
    return len > END - start ? END : start + len;  // a range that would run past the largest offset runs to the end
}

bool overlaps(uint64_t a0, uint64_t a1, uint64_t b0, uint64_t b1) { return a0 < b1 && b0 < a1; }

}  // namespace

bool LockTable::test(const std::string& key, uint64_t owner, const LockRange& want, LockInfo* blocking) {
    if (want.type == LockType::Unlock) return false;
    std::lock_guard<std::mutex> g(mu_);
    auto it = ranges_.find(key);
    if (it == ranges_.end()) return false;
    uint64_t w0 = want.start, w1 = end_of(want.start, want.len);
    const Held* first = nullptr;
    for (const Held& h : it->second) {
        if (h.owner == owner || !overlaps(w0, w1, h.start, h.end)) continue;
        if (want.type == LockType::Read && h.type == LockType::Read) continue;
        if (!first || h.start < first->start) first = &h;  // the one that starts first
    }
    if (!first) return false;
    if (blocking) {
        blocking->type = first->type;
        blocking->start = first->start;
        blocking->len = first->end == END ? 0 : first->end - first->start;
        blocking->owner = first->owner;
    }
    return true;
}

bool LockTable::set(const std::string& key, uint64_t owner, const LockRange& lk) {
    std::lock_guard<std::mutex> g(mu_);
    uint64_t s = lk.start, e = end_of(lk.start, lk.len);
    if (s >= e) return true;  // an empty range (it starts at the largest offset): nothing to lock or unlock
    auto& list = ranges_[key];
    if (lk.type != LockType::Unlock) {
        for (const Held& h : list)
            if (h.owner != owner && overlaps(s, e, h.start, h.end) && !(lk.type == LockType::Read && h.type == LockType::Read))
                return false;  // (a conflict means the list is not empty)
    }
    // the owner's locks over [s, e) are replaced: cut them out, keeping the parts outside
    std::vector<Held> out;
    for (const Held& h : list) {
        if (h.owner != owner || !overlaps(s, e, h.start, h.end)) {
            out.push_back(h);
            continue;
        }
        if (h.start < s) out.push_back({h.owner, h.type, h.start, s});
        if (h.end > e) out.push_back({h.owner, h.type, e, h.end});
    }
    if (lk.type != LockType::Unlock) out.push_back({owner, lk.type, s, e});
    // neighbours of the same owner and kind that touch or overlap become one lock
    std::sort(out.begin(), out.end(), [](const Held& a, const Held& b) { return a.owner != b.owner ? a.owner < b.owner : a.start < b.start; });
    std::vector<Held> merged;
    for (const Held& h : out) {
        if (!merged.empty() && merged.back().owner == h.owner && merged.back().type == h.type && h.start <= merged.back().end)
            merged.back().end = std::max(merged.back().end, h.end);
        else
            merged.push_back(h);
    }
    if (merged.empty())
        ranges_.erase(key);
    else
        list = merged;
    return true;
}

void LockTable::release_owner(const std::string& key, uint64_t owner) {
    std::lock_guard<std::mutex> g(mu_);
    auto it = ranges_.find(key);
    if (it == ranges_.end()) return;
    auto& v = it->second;
    v.erase(std::remove_if(v.begin(), v.end(), [&](const Held& h) { return h.owner == owner; }), v.end());
    if (v.empty()) ranges_.erase(it);
}

bool LockTable::flock_try(const std::string& key, uint64_t owner, LockType type) {
    std::lock_guard<std::mutex> g(mu_);
    if (type == LockType::Unlock) {
        auto it = flocks_.find(key);
        if (it != flocks_.end()) {
            it->second.erase(owner);
            if (it->second.empty()) flocks_.erase(it);
        }
        return true;
    }
    auto& m = flocks_[key];
    for (auto& kv : m)
        if (kv.first != owner && (type == LockType::Write || kv.second == LockType::Write)) return false;
    m[owner] = type;  // a new lock, or the owner's own converted
    return true;
}

void LockTable::flock_release(const std::string& key, uint64_t owner) { flock_try(key, owner, LockType::Unlock); }

size_t LockTable::count() {
    std::lock_guard<std::mutex> g(mu_);
    size_t n = 0;
    for (auto& kv : ranges_) n += kv.second.size();
    for (auto& kv : flocks_) n += kv.second.size();
    return n;
}

std::vector<LockInfo> LockTable::list(const std::string& key) {
    std::lock_guard<std::mutex> g(mu_);
    std::vector<LockInfo> out;
    auto it = ranges_.find(key);
    if (it == ranges_.end()) return out;
    for (const Held& h : it->second) out.push_back({h.type, h.start, h.end == END ? 0 : h.end - h.start, h.owner});
    std::sort(out.begin(), out.end(),
              [](const LockInfo& a, const LockInfo& b) { return a.owner != b.owner ? a.owner < b.owner : a.start < b.start; });
    return out;
}

bool LockTable::held(const std::string& key) {
    std::lock_guard<std::mutex> g(mu_);
    return ranges_.count(key) > 0 || flocks_.count(key) > 0;
}

}  // namespace tierfs
