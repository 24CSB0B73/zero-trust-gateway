#pragma once
#include <map>
#include <mutex>
#include <sstream>
#include <string>

namespace zt {

// Tiny Prometheus-text-format counter registry.
class Metrics {
 public:
  void inc(const std::string& series, double by = 1) {
    std::lock_guard<std::mutex> lk(mu_);
    v_[series] += by;
  }
  std::string render(const std::map<std::string, double>& extra_gauges = {}) {
    std::ostringstream o;
    {
      std::lock_guard<std::mutex> lk(mu_);
      for (const auto& kv : v_) o << kv.first << ' ' << kv.second << '\n';
    }
    for (const auto& kv : extra_gauges) o << kv.first << ' ' << kv.second << '\n';
    return o.str();
  }

 private:
  std::mutex mu_;
  std::map<std::string, double> v_;
};

}  // namespace zt
