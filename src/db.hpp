#pragma once
#include <libpq-fe.h>

#include <condition_variable>
#include <mutex>
#include <string>
#include <vector>

namespace zt {

struct DbResult {
  bool ok = false;
  std::string error;
  std::string sqlstate;  // e.g. "23505" = unique violation, "23503" = FK violation
  std::vector<std::vector<std::string>> rows;  // NULL is returned as ""
  long affected = 0;
};

// Fixed-size libpq connection pool. Every query goes through PQexecParams, so user
// input is NEVER concatenated into SQL text (parameterized queries only).
class Db {
 public:
  Db(const std::string& conninfo, size_t pool_size);
  ~Db();
  Db(const Db&) = delete;
  Db& operator=(const Db&) = delete;

  DbResult exec(const std::string& sql, const std::vector<std::string>& params = {});
  bool ping();

 private:
  PGconn* open_conn();
  PGconn* acquire();
  void release(PGconn* c);

  std::string conninfo_;
  std::mutex mu_;
  std::condition_variable cv_;
  std::vector<PGconn*> idle_;
  std::vector<PGconn*> all_;
};

}  // namespace zt
