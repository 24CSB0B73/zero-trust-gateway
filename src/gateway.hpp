#pragma once
#include <httplib.h>

#include <nlohmann/json.hpp>
#include <optional>
#include <string>

#include "config.hpp"
#include "db.hpp"
#include "limits.hpp"
#include "metrics.hpp"
#include "policy.hpp"

namespace zt {

struct AuthCtx {
  int64_t user_id = 0;
  std::string email, role, session_id;
};

enum class AuthStatus { Ok, Missing, Invalid, Expired, Revoked, Disabled, Unavailable };

struct AuthOutcome {
  AuthStatus status = AuthStatus::Invalid;
  AuthCtx ctx;
};

class Gateway {
 public:
  explicit Gateway(Config cfg);
  void bootstrap();  // create first admin + demo resources/policies from env
  int run();         // blocks until stop()
  void stop();

 private:
  using Req = httplib::Request;
  using Res = httplib::Response;
  using Handler = std::function<void(const Req&, Res&)>;

  void register_routes();
  httplib::Server::Handler wrap(const std::string& name, Handler h);

  // building blocks of the Zero Trust pipeline
  AuthOutcome authenticate(const Req& req);
  bool require_auth(const Req& req, Res& res, AuthCtx& ctx, const std::string& action,
                    std::optional<int64_t> resource_id = std::nullopt);
  bool require_admin(const Req& req, Res& res, AuthCtx& ctx, const std::string& action);
  bool audit(std::optional<int64_t> uid, const std::string& email, std::optional<int64_t> rid,
             const std::string& action, const std::string& decision, const std::string& reason,
             const std::string& ip);
  std::optional<ResourceEntry> load_resource(int64_t id);
  DeviceState load_device(const std::string& device_id, int64_t user_id);

  // handlers
  void h_register(const Req&, Res&);
  void h_login(const Req&, Res&);
  void h_logout(const Req&, Res&);
  void h_list_resources(const Req&, Res&);
  void h_access_resource(const Req&, Res&);
  void h_create_resource(const Req&, Res&);
  void h_upsert_policy(const Req&, Res&);
  void h_audit_logs(const Req&, Res&);
  void h_attest(const Req&, Res&);
  void h_enroll_device(const Req&, Res&);
  void h_user_status(const Req&, Res&, bool active);
  void h_user_role(const Req&, Res&);
  void h_revoke_sessions(const Req&, Res&);
  void h_metrics(const Req&, Res&);

  Config cfg_;
  Db db_;
  PolicyCache cache_;
  RateLimiter ip_limiter_;
  RateLimiter login_limiter_;
  LoginThrottle throttle_;     // per account: 5 failures -> lockout
  LoginThrottle ip_throttle_;  // per source IP: much higher threshold (NAT-friendly)
  Metrics metrics_;
  std::string dummy_hash_;
  httplib::Server svr_;
};

}  // namespace zt
