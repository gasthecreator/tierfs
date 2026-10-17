// Advisory file locks, emulated inside the daemon (ADR-0011). Pure data structure: no files, no waiting.
//
// Two separate tables per key (a file identity), because POSIX byte-range locks and BSD flock locks are different things:
//   byte-range  (fcntl F_SETLK/F_GETLK): owned by a lock owner; shared (read) or exclusive (write) over [start, end); an owner's own locks never
//   conflict with
//               each other; setting a lock replaces what the owner had over that range (split, merge, convert); unlocking a range removes it.
//   whole-file  (flock): one shared or exclusive lock per owner; an owner can convert its lock.
// Only TRYING is offered. A caller that wants to wait polls `set` / `flock_try` until it succeeds (the driver does, and stops when interrupted).
#pragma once

#include <cstdint>
#include <map>
#include <mutex>
#include <string>
#include <vector>

namespace tierfs {

enum class LockType { Read, Write, Unlock };

struct LockRange {
    LockType type = LockType::Read;
    uint64_t start = 0;
    uint64_t len = 0;  // 0: to the end of the file, whatever its size becomes
};

struct LockInfo {  // a lock that is in the way (F_GETLK)
    LockType type = LockType::Read;
    uint64_t start = 0;
    uint64_t len = 0;  // 0: to the end of the file
    uint64_t owner = 0;
};

class LockTable {
public:
    // F_GETLK: the first lock held by ANOTHER owner that conflicts with `want` (a Read or Write range), if any.
    bool test(const std::string& key, uint64_t owner, const LockRange& want, LockInfo* blocking);
    // F_SETLK: false if another owner's lock conflicts (nothing changes). An Unlock always succeeds.
    bool set(const std::string& key, uint64_t owner, const LockRange& lk);
    // The owner closed the file: all its byte-range locks on it go (POSIX: closing any descriptor of the file releases the process's locks).
    void release_owner(const std::string& key, uint64_t owner);

    // Everything held on `from` now belongs to `to` (a file got a second name: its locks move to the identity both names share). What `to` already
    // holds stays.
    void rekey(const std::string& from, const std::string& to);

    // flock: LockType::Read is LOCK_SH, Write is LOCK_EX. False if another owner holds a conflicting lock. Unlock always succeeds.
    bool flock_try(const std::string& key, uint64_t owner, LockType type);
    void flock_release(const std::string& key, uint64_t owner);

    // For tests and for `tierctl`: how many locks are held (ranges + flocks), whether anything is held on the key, and the byte-range locks on a key
    // (sorted by owner, then start; neighbours of one owner and kind are already one lock).
    size_t count();
    bool held(const std::string& key);
    std::vector<LockInfo> list(const std::string& key);

private:
    struct Held {
        uint64_t owner;
        LockType type;
        uint64_t start, end;
    };  // [start, end), end == UINT64_MAX: to the end of the file
    std::mutex mu_;
    std::map<std::string, std::vector<Held>> ranges_;
    std::map<std::string, std::map<uint64_t, LockType>> flocks_;
};

}  // namespace tierfs
