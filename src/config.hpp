#pragma once
#include <cstdlib>
#include <stdexcept>
#include <string>

namespace zt {

inline std::string env_or(const char* k, const std::string& d) {
  const char* v = std::getenv(k);
  return (v && *v) ? std::string(v) : d;
}

struct Config {
  int port = 8080;
  std::string db_conninfo;
  std::string jwt_secret;
  int jwt_ttl_sec = 900;  // short-lived access tokens: 15 min
  std::string admin_email, admin_password;
  std::string demo_upstream;
  size_t pool_size = 16;
  size_t threads = 32;
  double rate_rps = 50, rate_burst = 100;         // per-IP, all endpoints
  double login_rps = 2, login_burst = 20;         // per-IP, /auth/login (protects PBKDF2 CPU)
  int lock_max_failures = 5, lock_window_sec = 300, lock_duration_sec = 300;
  int pbkdf2_iters = 210000;
  int policy_ttl_sec = 30;
  int upstream_timeout_sec = 5;
  std::string web_dir = "./web";

  static Config from_env() {
    Config c;
    c.port = std::stoi(env_or("PORT", "8080"));
    c.db_conninfo = env_or("DATABASE_URL", "postgresql://zt:zt@127.0.0.1:5432/ztgw");
    c.jwt_secret = env_or("JWT_SECRET", "");
    if (c.jwt_secret.size() < 32)
      throw std::runtime_error("JWT_SECRET must be set and at least 32 characters long");
    c.jwt_ttl_sec = std::stoi(env_or("JWT_TTL_SEC", "900"));
    c.admin_email = env_or("ADMIN_EMAIL", "");
    c.admin_password = env_or("ADMIN_PASSWORD", "");
    c.demo_upstream = env_or("DEMO_UPSTREAM", "");
    c.pool_size = std::stoul(env_or("POOL_SIZE", "16"));
    c.threads = std::stoul(env_or("THREADS", "32"));
    c.rate_rps = std::stod(env_or("RATE_RPS", "50"));
    c.rate_burst = std::stod(env_or("RATE_BURST", "100"));
    c.login_rps = std::stod(env_or("LOGIN_RPS", "2"));
    c.login_burst = std::stod(env_or("LOGIN_BURST", "20"));
    c.pbkdf2_iters = std::stoi(env_or("PBKDF2_ITERS", "210000"));
    c.policy_ttl_sec = std::stoi(env_or("POLICY_TTL_SEC", "30"));
    c.web_dir = env_or("WEB_DIR", "./web");
    return c;
  }
};

}  // namespace zt
