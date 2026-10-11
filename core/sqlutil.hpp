// Small RAII wrappers around SQLite shared by the metadata and chunk stores.
#pragma once

#include <sqlite3.h>

#include <cstdint>
#include <cstdio>
#include <string>

namespace tierfs {
namespace sql {

// Prepared statement with RAII cleanup and chainable binds. Binds copy the
// text (SQLITE_TRANSIENT) because our std::strings do not outlive the call.
class Stmt {
public:
    Stmt(sqlite3* db, const char* sql) : db_(db) {
        if (sqlite3_prepare_v2(db, sql, -1, &s_, nullptr) != SQLITE_OK) {
            fprintf(stderr, "tierfs meta: prepare failed: %s\n", sqlite3_errmsg(db));
            s_ = nullptr;
        }
    }
    ~Stmt() { if (s_) sqlite3_finalize(s_); }
    Stmt(const Stmt&) = delete;
    Stmt& operator=(const Stmt&) = delete;

    Stmt& text(int i, const std::string& v) {
        if (s_) sqlite3_bind_text(s_, i, v.data(), static_cast<int>(v.size()), SQLITE_TRANSIENT);
        return *this;
    }
    Stmt& num(int i, int64_t v) {
        if (s_) sqlite3_bind_int64(s_, i, v);
        return *this;
    }
    Stmt& null(int i) {
        if (s_) sqlite3_bind_null(s_, i);
        return *this;
    }
    // For INSERT/UPDATE/DELETE.
    bool run() {
        if (!s_) return false;
        if (sqlite3_step(s_) == SQLITE_DONE) return true;
        fprintf(stderr, "tierfs meta: write failed: %s\n", sqlite3_errmsg(db_));
        return false;
    }
    // For SELECT: true while a row is available.
    bool row() { return s_ && sqlite3_step(s_) == SQLITE_ROW; }
    int64_t col_num(int i) { return sqlite3_column_int64(s_, i); }
    bool col_null(int i) { return sqlite3_column_type(s_, i) == SQLITE_NULL; }
    double col_real(int i) { return sqlite3_column_double(s_, i); }
    Stmt& real(int i, double v) {
        if (s_) sqlite3_bind_double(s_, i, v);
        return *this;
    }
    bool valid() const { return s_ != nullptr; }
    std::string col_text(int i) {
        const unsigned char* t = sqlite3_column_text(s_, i);
        return std::string(reinterpret_cast<const char*>(t), sqlite3_column_bytes(s_, i));
    }

private:
    sqlite3* db_;
    sqlite3_stmt* s_ = nullptr;
};

// BEGIN ... COMMIT as one unit: either the whole directory listing is stored
// or none of it, even if we crash half way. Rolls back unless commit() ran.
class Txn {
public:
    explicit Txn(sqlite3* db) : db_(db) {
        active_ = began_ = sqlite3_exec(db_, "BEGIN IMMEDIATE", nullptr, nullptr, nullptr) == SQLITE_OK;
    }
    ~Txn() { if (active_) sqlite3_exec(db_, "ROLLBACK", nullptr, nullptr, nullptr); }
    // True only if the transaction is durably committed. On failure the
    // destructor rolls back, so callers must treat false as "nothing happened".
    bool commit() {
        if (active_ && sqlite3_exec(db_, "COMMIT", nullptr, nullptr, nullptr) == SQLITE_OK)
            active_ = false;
        return !active_ && began_;
    }
    bool began() const { return began_; }
private:
    sqlite3* db_;
    bool active_ = false;
    bool began_ = false;
};

}  // namespace sql
}  // namespace tierfs
