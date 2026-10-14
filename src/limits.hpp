#pragma once
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <mutex>
#include <string>
#include <unordered_map>

namespace zt {

inline double steady_seconds() {
  using namespace std::chrono;
  return duration<double>(steady_clock::now().time_since_epoch()).count();
}

// Token bucket per key (e.g. client IP). Thread-safe.
class RateLimiter {
 public:
  RateLimiter(double capacity, double refill_per_sec) : cap_(capacity), rate_(refill_per_sec) {}

  bool allow(const std::string& key) { return allow(key, steady_seconds()); }

  bool allow(const std::string& key, double now) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = buckets_.find(key);
    if (it == buckets_.end()) {
      if (buckets_.size() >= kMaxKeys) sweep(now);
      it = buckets_.emplace(key, Bucket{cap_, now}).first;
    }
    Bucket& b = it->second;
    b.tokens = std::min(cap_, b.tokens + (now - b.last) * rate_);
    b.last = now;
    if (b.tokens >= 1.0) {
      b.tokens -= 1.0;
      return true;
    }
    return false;
  }

 private:
  struct Bucket {
    double tokens;
    double last;
  };
  static constexpr size_t kMaxKeys = 100000;
  void sweep(double now) {
    for (auto it = buckets_.begin(); it != buckets_.end();) {
      if (it->second.tokens + (now - it->second.last) * rate_ >= cap_) it = buckets_.erase(it);
      else ++it;
    }
    if (buckets_.size() >= kMaxKeys) buckets_.erase(buckets_.begin());
  }
  double cap_, rate_;
  std::mutex mu_;
  std::unordered_map<std::string, Bucket> buckets_;
};

// Brute-force protection: N failures inside a window => lockout.
class LoginThrottle {
 public:
  LoginThrottle(int max_failures, int window_sec, int lockout_sec)
      : max_(max_failures), window_(window_sec), lockout_(lockout_sec) {}

  // Seconds the caller must wait; 0 if allowed.
  int blocked_for(const std::string& key, int64_t now) {
    std::lock_guard<std::mutex> lk(mu_);
    auto it = m_.find(key);
    if (it == m_.end() || it->second.locked_until <= now) return 0;
    return static_cast<int>(it->second.locked_until - now);
  }

  void record_failure(const std::string& key, int64_t now) {
    std::lock_guard<std::mutex> lk(mu_);
    if (m_.size() > 100000) m_.clear();
    Entry& e = m_[key];
    if (now - e.window_start > window_) {
      e.count = 0;
      e.window_start = now;
    }
    if (++e.count >= max_) {
      e.locked_until = now + lockout_;
      e.count = 0;
      e.window_start = now;
    }
  }

  void record_success(const std::string& key) {
    std::lock_guard<std::mutex> lk(mu_);
    m_.erase(key);
  }

 private:
  struct Entry {
    int count = 0;
    int64_t window_start = 0;
    int64_t locked_until = 0;
  };
  int max_, window_, lockout_;
  std::mutex mu_;
  std::unordered_map<std::string, Entry> m_;
};

}  // namespace zt
