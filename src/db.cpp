#include "db.hpp"

#include <chrono>
#include <stdexcept>

namespace zt {

PGconn* Db::open_conn() {
  PGconn* c = PQconnectdb(conninfo_.c_str());
  if (PQstatus(c) != CONNECTION_OK) {
    std::string err = PQerrorMessage(c);
    PQfinish(c);
    throw std::runtime_error("db connect failed: " + err);
  }
  // Safe error handling: no query may run forever and hold a pooled connection hostage.
  PGresult* r = PQexec(c, "SET statement_timeout = 3000");
  PQclear(r);
  return c;
}

Db::Db(const std::string& conninfo, size_t pool_size) : conninfo_(conninfo) {
  for (size_t i = 0; i < pool_size; ++i) {
    PGconn* c = open_conn();
    all_.push_back(c);
    idle_.push_back(c);
  }
}

Db::~Db() {
  for (PGconn* c : all_) PQfinish(c);
}

PGconn* Db::acquire() {
  std::unique_lock<std::mutex> lk(mu_);
  if (!cv_.wait_for(lk, std::chrono::seconds(3), [&] { return !idle_.empty(); }))
    return nullptr;  // pool exhausted -> caller fails closed with 503
  PGconn* c = idle_.back();
  idle_.pop_back();
  lk.unlock();
  if (PQstatus(c) != CONNECTION_OK) {
    PQreset(c);
    if (PQstatus(c) == CONNECTION_OK) {
      PGresult* r = PQexec(c, "SET statement_timeout = 3000");
      PQclear(r);
    }
  }
  return c;
}

void Db::release(PGconn* c) {
  {
    std::lock_guard<std::mutex> lk(mu_);
    idle_.push_back(c);
  }
  cv_.notify_one();
}

DbResult Db::exec(const std::string& sql, const std::vector<std::string>& params) {
  DbResult out;
  PGconn* c = acquire();
  if (!c) {
    out.error = "db pool exhausted";
    return out;
  }
  std::vector<const char*> vals;
  vals.reserve(params.size());
  for (const auto& p : params) vals.push_back(p.c_str());

  PGresult* r = PQexecParams(c, sql.c_str(), static_cast<int>(vals.size()), nullptr,
                             vals.data(), nullptr, nullptr, 0);
  ExecStatusType st = PQresultStatus(r);
  if (st == PGRES_TUPLES_OK) {
    out.ok = true;
    int n = PQntuples(r), m = PQnfields(r);
    out.rows.reserve(n);
    for (int i = 0; i < n; ++i) {
      std::vector<std::string> row;
      row.reserve(m);
      for (int j = 0; j < m; ++j) row.emplace_back(PQgetisnull(r, i, j) ? "" : PQgetvalue(r, i, j));
      out.rows.push_back(std::move(row));
    }
    out.affected = n;
  } else if (st == PGRES_COMMAND_OK) {
    out.ok = true;
    out.affected = std::atol(PQcmdTuples(r));
  } else {
    out.error = PQerrorMessage(c);
    const char* ss = PQresultErrorField(r, PG_DIAG_SQLSTATE);
    if (ss) out.sqlstate = ss;
  }
  PQclear(r);
  release(c);
  return out;
}

bool Db::ping() { return exec("SELECT 1").ok; }

}  // namespace zt
