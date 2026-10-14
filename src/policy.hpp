#pragma once
#include <atomic>
#include <cstdint>
#include <functional>
#include <optional>
#include <shared_mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace zt {

struct Policy {
  int64_t id = 0;
  int64_t resource_id = 0;
  std::vector<std::string> allowed_roles;
  bool require_healthy_device = true;
  int max_posture_age_sec = 900;
  bool active = true;
};

// Everything known about the caller, re-read from the DB on every request.
struct Subject {
  int64_t user_id = 0;
  std::string role;
  bool active = false;
};

struct DeviceState {
  bool known = false;             // device id is enrolled
  bool owned_by_subject = false;  // enrolled to THIS user
  bool healthy = false;           // last verified posture report was fully healthy
  int64_t last_check = 0;         // epoch seconds of last accepted report
};

struct Decision {
  bool allow = false;
  std::string reason;
};

// Pure function (no I/O) => trivially unit-testable.
// DEFAULT DENY: the only path to allow=true is the last line.
Decision evaluate(const Subject& s, const std::optional<Policy>& policy,
                  const DeviceState& device, int64_t now);

struct ResourceEntry {
  int64_t id = 0;
  std::string name;
  std::string upstream_url;
  std::optional<Policy> policy;
};

// Read-mostly cache of resource+policy with TTL and explicit invalidation.
// A generation counter prevents the classic race where a slow loader writes stale
// data back AFTER an invalidation.
class PolicyCache {
 public:
  using Loader = std::function<std::optional<ResourceEntry>(int64_t)>;  // may throw
  PolicyCache(Loader loader, int ttl_sec) : loader_(std::move(loader)), ttl_(ttl_sec) {}

  std::optional<ResourceEntry> get(int64_t id, int64_t now);
  void invalidate(int64_t id);
  void invalidate_all();

  uint64_t hits() const { return hits_.load(); }
  uint64_t misses() const { return misses_.load(); }

 private:
  struct Slot {
    ResourceEntry value;
    int64_t expires = 0;
  };
  Loader loader_;
  int ttl_;
  std::shared_mutex mu_;
  std::unordered_map<int64_t, Slot> map_;
  std::atomic<uint64_t> generation_{0};
  std::atomic<uint64_t> hits_{0}, misses_{0};
};

}  // namespace zt
