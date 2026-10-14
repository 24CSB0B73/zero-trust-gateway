#include "policy.hpp"

#include <algorithm>
#include <mutex>

namespace zt {

Decision evaluate(const Subject& s, const std::optional<Policy>& policy,
                  const DeviceState& device, int64_t now) {
  if (!s.active) return {false, "account_disabled"};
  if (!policy) return {false, "no_policy"};
  if (!policy->active) return {false, "policy_inactive"};

  const auto& roles = policy->allowed_roles;
  if (std::find(roles.begin(), roles.end(), s.role) == roles.end())
    return {false, "role_not_permitted"};

  if (policy->require_healthy_device) {
    if (!device.known) return {false, "device_missing"};
    if (!device.owned_by_subject) return {false, "device_not_owned"};
    if (!device.healthy) return {false, "device_unhealthy"};
    if (now - device.last_check > policy->max_posture_age_sec)
      return {false, "device_posture_stale"};
  }
  return {true, "policy_satisfied"};
}

std::optional<ResourceEntry> PolicyCache::get(int64_t id, int64_t now) {
  {
    std::shared_lock<std::shared_mutex> lk(mu_);
    auto it = map_.find(id);
    if (it != map_.end() && it->second.expires > now) {
      hits_++;
      return it->second.value;
    }
  }
  misses_++;
  const uint64_t gen = generation_.load();
  auto loaded = loader_(id);  // DB read happens OUTSIDE any lock
  if (loaded) {
    std::unique_lock<std::shared_mutex> lk(mu_);
    // Only publish if nobody invalidated while we were reading.
    if (generation_.load() == gen) map_[id] = Slot{*loaded, now + ttl_};
  }
  return loaded;
}

void PolicyCache::invalidate(int64_t id) {
  std::unique_lock<std::shared_mutex> lk(mu_);
  generation_++;
  map_.erase(id);
}

void PolicyCache::invalidate_all() {
  std::unique_lock<std::shared_mutex> lk(mu_);
  generation_++;
  map_.clear();
}

}  // namespace zt
