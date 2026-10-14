#include "gateway.hpp"

#include <algorithm>
#include <iostream>
#include <regex>

#include "crypto.hpp"

using json = nlohmann::json;

namespace zt {
namespace {

struct BadRequest : std::runtime_error {
  using std::runtime_error::runtime_error;
};

void send_json(httplib::Response& res, int status, const json& body) {
  res.status = status;
  res.set_content(body.dump(), "application/json");
}
void send_err(httplib::Response& res, int status, const std::string& code) {
  send_json(res, status, json{{"error", code}});
}

std::string lower(std::string s) {
  std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
  return s;
}

// ---- input validation (allow-list style) ----
bool valid_email(const std::string& e) {
  static const std::regex re(R"(^[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,180}\.[A-Za-z]{2,24}$)");
  return e.size() <= 254 && std::regex_match(e, re);
}
bool valid_role(const std::string& r) {
  static const std::regex re("^[a-z_]{1,32}$");
  return std::regex_match(r, re);
}
bool valid_device_id(const std::string& d) {
  static const std::regex re("^[A-Za-z0-9_-]{8,64}$");
  return std::regex_match(d, re);
}
bool valid_name(const std::string& n) {
  static const std::regex re("^[A-Za-z0-9 _.-]{1,64}$");
  return std::regex_match(n, re);
}
bool parse_id(const std::string& s, int64_t& out) {
  if (s.empty() || s.size() > 18) return false;
  for (char c : s)
    if (c < '0' || c > '9') return false;
  out = std::stoll(s);
  return out > 0;
}
bool parse_upstream(const std::string& url, std::string& origin, std::string& path) {
  static const std::regex re(R"(^(http://[A-Za-z0-9.-]{1,253}(:[0-9]{1,5})?)(/[^\s]*)?$)");
  std::smatch m;
  if (!std::regex_match(url, m, re)) return false;
  origin = m[1];
  path = m[3].matched ? m[3].str() : "/";
  return true;
}

json parse_body(const httplib::Request& req) {
  if (req.body.empty()) throw BadRequest("empty_body");
  json j = json::parse(req.body);  // json::exception -> 400
  if (!j.is_object()) throw BadRequest("body_must_be_object");
  return j;
}
std::string get_str(const json& j, const char* k, size_t maxlen) {
  auto it = j.find(k);
  if (it == j.end() || !it->is_string()) throw BadRequest(std::string("invalid_") + k);
  std::string s = it->get<std::string>();
  if (s.size() > maxlen) throw BadRequest(std::string("invalid_") + k);
  return s;
}
bool get_bool(const json& j, const char* k, std::optional<bool> def = std::nullopt) {
  auto it = j.find(k);
  if (it == j.end()) {
    if (def) return *def;
    throw BadRequest(std::string("missing_") + k);
  }
  if (!it->is_boolean()) throw BadRequest(std::string("invalid_") + k);
  return it->get<bool>();
}
int64_t get_int(const json& j, const char* k, int64_t lo, int64_t hi,
                std::optional<int64_t> def = std::nullopt) {
  auto it = j.find(k);
  if (it == j.end()) {
    if (def) return *def;
    throw BadRequest(std::string("missing_") + k);
  }
  if (!it->is_number_integer()) throw BadRequest(std::string("invalid_") + k);
  int64_t v = it->get<int64_t>();
  if (v < lo || v > hi) throw BadRequest(std::string("invalid_") + k);
  return v;
}

std::string reason_of(AuthStatus s) {
  switch (s) {
    case AuthStatus::Missing: return "token_missing";
    case AuthStatus::Invalid: return "token_invalid";
    case AuthStatus::Expired: return "token_expired";
    case AuthStatus::Revoked: return "session_revoked";
    case AuthStatus::Disabled: return "account_disabled";
    case AuthStatus::Unavailable: return "auth_backend_unavailable";
    default: return "ok";
  }
}

std::vector<std::string> split(const std::string& s, char d) {
  std::vector<std::string> out;
  if (s.empty()) return out;
  size_t st = 0, p;
  while ((p = s.find(d, st)) != std::string::npos) {
    out.push_back(s.substr(st, p - st));
    st = p + 1;
  }
  out.push_back(s.substr(st));
  return out;
}

std::string pg_array(const std::vector<std::string>& v) {
  std::string a = "{";
  for (size_t i = 0; i < v.size(); ++i) a += (i ? "," : "") + v[i];  // roles are validated [a-z_]
  return a + "}";
}

}  // namespace

// ---------------------------------------------------------------------------------------
Gateway::Gateway(Config cfg)
    : cfg_(std::move(cfg)),
      db_(cfg_.db_conninfo, cfg_.pool_size),
      cache_([this](int64_t id) { return load_resource(id); }, cfg_.policy_ttl_sec),
      ip_limiter_(cfg_.rate_burst, cfg_.rate_rps),
      login_limiter_(cfg_.login_burst, cfg_.login_rps),
      throttle_(cfg_.lock_max_failures, cfg_.lock_window_sec, cfg_.lock_duration_sec),
      ip_throttle_(cfg_.lock_max_failures * 10, cfg_.lock_window_sec, cfg_.lock_duration_sec) {
  dummy_hash_ = hash_password("not-a-real-password", cfg_.pbkdf2_iters);
  register_routes();
}

void Gateway::stop() { svr_.stop(); }

int Gateway::run() {
  std::cout << "[gateway] listening on 0.0.0.0:" << cfg_.port << " threads=" << cfg_.threads
            << " db_pool=" << cfg_.pool_size << std::endl;
  return svr_.listen("0.0.0.0", cfg_.port) ? 0 : 1;
}

void Gateway::bootstrap() {
  if (!cfg_.admin_email.empty() && !cfg_.admin_password.empty()) {
    auto r = db_.exec(
        "INSERT INTO users(email,password_hash,role) VALUES($1,$2,'admin') "
        "ON CONFLICT (email) DO NOTHING",
        {lower(cfg_.admin_email), hash_password(cfg_.admin_password, cfg_.pbkdf2_iters)});
    if (!r.ok) throw std::runtime_error("bootstrap admin failed: " + r.error);
    if (r.affected) std::cout << "[bootstrap] created admin " << cfg_.admin_email << std::endl;
  }
  if (!cfg_.demo_upstream.empty()) {
    auto c = db_.exec("SELECT count(*) FROM resources");
    if (c.ok && !c.rows.empty() && c.rows[0][0] == "0") {
      auto seed = [&](const std::string& name, const std::string& path,
                      const std::vector<std::string>& roles, bool device) {
        auto r = db_.exec("INSERT INTO resources(name, upstream_url) VALUES($1,$2) RETURNING id",
                          {name, cfg_.demo_upstream + path});
        if (!r.ok) throw std::runtime_error("seed resource failed: " + r.error);
        auto p = db_.exec(
            "INSERT INTO policies(resource_id, allowed_roles, require_healthy_device) "
            "VALUES($1::bigint,$2::text[],$3::boolean)",
            {r.rows[0][0], pg_array(roles), device ? "true" : "false"});
        if (!p.ok) throw std::runtime_error("seed policy failed: " + p.error);
      };
      seed("hr-portal", "/hr", {"employee", "admin"}, true);
      seed("finance-reports", "/finance", {"admin"}, true);
      seed("public-wiki", "/wiki", {"employee", "contractor", "admin"}, false);
      std::cout << "[bootstrap] seeded demo resources" << std::endl;
    }
  }
}

// ---------------------------------------------------------------------------------------
// Pipeline building blocks
// ---------------------------------------------------------------------------------------
AuthOutcome Gateway::authenticate(const Req& req) {
  AuthOutcome out;
  std::string h = req.get_header_value("Authorization");
  if (h.rfind("Bearer ", 0) != 0) {
    out.status = AuthStatus::Missing;
    return out;
  }
  std::string token = h.substr(7);
  if (token.empty() || token.size() > 4096) {
    out.status = AuthStatus::Invalid;
    return out;
  }
  json claims;
  JwtStatus js = jwt_verify(token, cfg_.jwt_secret, claims);
  if (js == JwtStatus::Expired) {
    out.status = AuthStatus::Expired;
    return out;
  }
  if (js != JwtStatus::Ok) {
    out.status = AuthStatus::Invalid;
    return out;
  }
  int64_t uid = 0;
  std::string jti = claims["jti"].get<std::string>();
  if (!parse_id(claims["sub"].get<std::string>(), uid) || jti.size() > 64) {
    out.status = AuthStatus::Invalid;
    return out;
  }
  // The token alone is NOT enough: the session and the account are re-checked in the DB on
  // every request. That is what makes logout, disable and revoke take effect immediately.
  auto r = db_.exec(
      "SELECT u.email, u.role, u.active, s.revoked, (s.expires_at > now()) "
      "FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id=$1 AND s.user_id=$2::bigint",
      {jti, std::to_string(uid)});
  if (!r.ok) {
    out.status = AuthStatus::Unavailable;
    return out;
  }
  if (r.rows.empty()) {
    out.status = AuthStatus::Invalid;
    return out;
  }
  const auto& row = r.rows[0];
  if (row[3] == "t") out.status = AuthStatus::Revoked;
  else if (row[4] != "t") out.status = AuthStatus::Expired;
  else if (row[2] != "t") out.status = AuthStatus::Disabled;
  else out.status = AuthStatus::Ok;
  out.ctx = AuthCtx{uid, row[0], row[1], jti};  // role comes from the DB, never from the token
  return out;
}

bool Gateway::audit(std::optional<int64_t> uid, const std::string& email,
                    std::optional<int64_t> rid, const std::string& action,
                    const std::string& decision, const std::string& reason,
                    const std::string& ip) {
  metrics_.inc("zt_events_total{action=\"" + action + "\",decision=\"" + decision +
               "\",reason=\"" + reason + "\"}");
  auto r = db_.exec(
      "INSERT INTO audit_logs(user_id,email,resource_id,action,decision,reason,ip) "
      "VALUES(NULLIF($1::text,'')::bigint,$2,NULLIF($3::text,'')::bigint,$4,$5,$6,$7)",
      {uid ? std::to_string(*uid) : "", email, rid ? std::to_string(*rid) : "", action, decision,
       reason, ip});
  if (!r.ok) std::cerr << "[audit] WRITE FAILED: " << r.error << std::endl;
  return r.ok;
}

bool Gateway::require_auth(const Req& req, Res& res, AuthCtx& ctx, const std::string& action,
                           std::optional<int64_t> rid) {
  AuthOutcome a = authenticate(req);
  if (a.status == AuthStatus::Ok) {
    ctx = a.ctx;
    return true;
  }
  if (a.status == AuthStatus::Unavailable) {
    send_err(res, 503, "service_unavailable");
    return false;
  }
  std::optional<int64_t> uid;
  if (a.ctx.user_id) uid = a.ctx.user_id;
  audit(uid, a.ctx.email, rid, action, "deny", reason_of(a.status), req.remote_addr);
  res.set_header("WWW-Authenticate", "Bearer");
  send_err(res, 401, "unauthorized");  // deliberately identical for every failure cause
  return false;
}

bool Gateway::require_admin(const Req& req, Res& res, AuthCtx& ctx, const std::string& action) {
  if (!require_auth(req, res, ctx, action)) return false;
  if (ctx.role != "admin") {
    audit(ctx.user_id, ctx.email, std::nullopt, action, "deny", "admin_required", req.remote_addr);
    send_err(res, 403, "forbidden");
    return false;
  }
  return true;
}

std::optional<ResourceEntry> Gateway::load_resource(int64_t id) {
  auto r = db_.exec(
      "SELECT r.id::text, r.name, r.upstream_url, COALESCE(p.id::text,''), "
      "COALESCE(array_to_string(p.allowed_roles,','),''), "
      "COALESCE(p.require_healthy_device::text,''), COALESCE(p.max_posture_age_sec::text,''), "
      "COALESCE(p.active::text,'') "
      "FROM resources r LEFT JOIN policies p ON p.resource_id = r.id WHERE r.id=$1::bigint",
      {std::to_string(id)});
  if (!r.ok) throw std::runtime_error("db error loading resource");
  if (r.rows.empty()) return std::nullopt;
  const auto& w = r.rows[0];
  ResourceEntry e;
  e.id = id;
  e.name = w[1];
  e.upstream_url = w[2];
  if (!w[3].empty()) {
    Policy p;
    p.id = std::stoll(w[3]);
    p.resource_id = id;
    p.allowed_roles = split(w[4], ',');
    p.require_healthy_device = (w[5] == "true");
    p.max_posture_age_sec = std::stoi(w[6]);
    p.active = (w[7] == "true");
    e.policy = p;
  }
  return e;
}

DeviceState Gateway::load_device(const std::string& device_id, int64_t user_id) {
  DeviceState d;
  auto r = db_.exec(
      "SELECT d.user_id::text, COALESCE(s.healthy::text,'false'), "
      "COALESCE(extract(epoch from s.last_check)::bigint::text,'0') "
      "FROM devices d LEFT JOIN device_status s ON s.device_id = d.id WHERE d.id=$1",
      {device_id});
  if (!r.ok || r.rows.empty()) return d;
  d.known = true;
  d.owned_by_subject = (r.rows[0][0] == std::to_string(user_id));
  d.healthy = (r.rows[0][1] == "true");
  d.last_check = std::stoll(r.rows[0][2]);
  return d;
}

// ---------------------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------------------
httplib::Server::Handler Gateway::wrap(const std::string& name, Handler h) {
  return [this, name, h](const Req& req, Res& res) {
    auto t0 = std::chrono::steady_clock::now();
    try {
      h(req, res);
    } catch (const json::exception&) {
      send_err(res, 400, "invalid_json");
    } catch (const BadRequest& e) {
      send_err(res, 400, e.what());
    } catch (const std::exception& e) {
      std::cerr << "[error] " << name << ": " << e.what() << std::endl;
      send_err(res, 500, "internal_error");  // never leak internals to the client
    }
    double secs = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    metrics_.inc("zt_http_requests_total{route=\"" + name + "\",status=\"" +
                 std::to_string(res.status) + "\"}");
    metrics_.inc("zt_request_seconds_sum", secs);
    metrics_.inc("zt_request_seconds_count");
  };
}

void Gateway::register_routes() {
  svr_.new_task_queue = [n = cfg_.threads] { return new httplib::ThreadPool(n); };
  svr_.set_payload_max_length(64 * 1024);
  svr_.set_read_timeout(5, 0);
  svr_.set_write_timeout(5, 0);
  svr_.set_idle_interval(1, 0);
  svr_.set_keep_alive_timeout(5);
  svr_.set_mount_point("/ui", cfg_.web_dir);

  svr_.set_pre_routing_handler([this](const Req& req, Res& res) {
    if (req.path == "/healthz" || req.path.rfind("/ui", 0) == 0)
      return httplib::Server::HandlerResponse::Unhandled;
    if (!ip_limiter_.allow(req.remote_addr)) {
      metrics_.inc("zt_rate_limited_total");
      res.set_header("Retry-After", "1");
      send_err(res, 429, "rate_limited");
      return httplib::Server::HandlerResponse::Handled;
    }
    return httplib::Server::HandlerResponse::Unhandled;
  });
  svr_.set_post_routing_handler([](const Req&, Res& res) {
    res.set_header("Cache-Control", "no-store");
    res.set_header("X-Content-Type-Options", "nosniff");
  });
  svr_.set_error_handler([](const Req&, Res& res) {
    if (res.body.empty()) send_err(res, res.status, res.status == 404 ? "not_found" : "error");
  });
  svr_.set_exception_handler([](const Req&, Res& res, std::exception_ptr) {
    send_err(res, 500, "internal_error");
  });

  svr_.Get("/", [](const Req&, Res& res) { res.set_redirect("/ui/dashboard.html"); });
  svr_.Get("/healthz", [this](const Req&, Res& res) {
    if (db_.ping()) send_json(res, 200, json{{"status", "ok"}});
    else send_err(res, 503, "db_unavailable");
  });

  auto bind = [this](auto fn) { return [this, fn](const Req& a, Res& b) { (this->*fn)(a, b); }; };
  svr_.Post("/auth/register", wrap("register", bind(&Gateway::h_register)));
  svr_.Post("/auth/login", wrap("login", bind(&Gateway::h_login)));
  svr_.Post("/auth/logout", wrap("logout", bind(&Gateway::h_logout)));
  svr_.Get("/resources", wrap("list_resources", bind(&Gateway::h_list_resources)));
  svr_.Get(R"(/resources/:id)", wrap("access_resource", bind(&Gateway::h_access_resource)));
  svr_.Post("/resources", wrap("create_resource", bind(&Gateway::h_create_resource)));
  svr_.Post("/policies", wrap("upsert_policy", bind(&Gateway::h_upsert_policy)));
  svr_.Get("/audit-logs", wrap("audit_logs", bind(&Gateway::h_audit_logs)));
  svr_.Post("/device/attest", wrap("attest", bind(&Gateway::h_attest)));
  svr_.Post("/admin/devices", wrap("enroll_device", bind(&Gateway::h_enroll_device)));
  svr_.Post("/admin/users/:id/disable",
            wrap("disable_user", [this](const Req& a, Res& b) { h_user_status(a, b, false); }));
  svr_.Post("/admin/users/:id/enable",
            wrap("enable_user", [this](const Req& a, Res& b) { h_user_status(a, b, true); }));
  svr_.Post("/admin/users/:id/role", wrap("set_role", bind(&Gateway::h_user_role)));
  svr_.Post("/admin/users/:id/revoke-sessions",
            wrap("revoke_sessions", bind(&Gateway::h_revoke_sessions)));
  svr_.Get("/metrics", wrap("metrics", bind(&Gateway::h_metrics)));
}

// ---------------------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------------------
void Gateway::h_register(const Req& req, Res& res) {
  json b = parse_body(req);
  std::string email = lower(get_str(b, "email", 254));
  std::string pw = get_str(b, "password", 128);
  if (!valid_email(email)) throw BadRequest("invalid_email");
  if (pw.size() < 10) throw BadRequest("password_too_short");

  // Role is never client-controlled: new accounts are always 'employee'.
  auto r = db_.exec(
      "INSERT INTO users(email,password_hash) VALUES($1,$2) RETURNING id, role",
      {email, hash_password(pw, cfg_.pbkdf2_iters)});
  if (!r.ok) {
    if (r.sqlstate == "23505") {
      send_err(res, 409, "email_taken");
      return;
    }
    send_err(res, 503, "service_unavailable");
    return;
  }
  audit(std::stoll(r.rows[0][0]), email, std::nullopt, "register", "allow", "registered",
        req.remote_addr);
  send_json(res, 201, json{{"id", std::stoll(r.rows[0][0])}, {"email", email}, {"role", r.rows[0][1]}});
}

void Gateway::h_login(const Req& req, Res& res) {
  const std::string ip = req.remote_addr;
  if (!login_limiter_.allow(ip)) {
    metrics_.inc("zt_rate_limited_total");
    res.set_header("Retry-After", "1");
    send_err(res, 429, "rate_limited");
    return;
  }
  json b = parse_body(req);
  std::string email = lower(get_str(b, "email", 254));
  std::string pw = get_str(b, "password", 128);
  int64_t now = now_sec();

  int wait = std::max(ip_throttle_.blocked_for(ip, now), throttle_.blocked_for(email, now));
  if (wait > 0) {
    audit(std::nullopt, email, std::nullopt, "login", "deny", "login_locked", ip);
    res.set_header("Retry-After", std::to_string(wait));
    send_err(res, 429, "login_locked");
    return;
  }

  auto r = db_.exec("SELECT id, password_hash, role, active FROM users WHERE email=$1", {email});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  const bool found = !r.rows.empty();
  // Always run PBKDF2 (against a dummy hash if the user is unknown) so response time does not
  // reveal whether an account exists.
  const bool pw_ok = verify_password(pw, found ? r.rows[0][1] : dummy_hash_);
  const bool active = found && r.rows[0][3] == "t";

  if (!found || !pw_ok || !active) {
    ip_throttle_.record_failure(ip, now);
    throttle_.record_failure(email, now);
    metrics_.inc("zt_login_failures_total");
    std::optional<int64_t> uid;
    if (found) uid = std::stoll(r.rows[0][0]);
    audit(uid, email, std::nullopt, "login", "deny", (found && pw_ok && !active) ? "account_disabled" : "bad_credentials", ip);
    send_err(res, 401, "invalid_credentials");
    return;
  }

  throttle_.record_success(email);
  const int64_t uid = std::stoll(r.rows[0][0]);
  const std::string role = r.rows[0][2];
  const std::string jti = random_hex(16);
  const int64_t exp = now + cfg_.jwt_ttl_sec;

  auto s = db_.exec(
      "INSERT INTO sessions(id,user_id,expires_at,ip) "
      "VALUES($1,$2::bigint,to_timestamp($3::double precision),$4)",
      {jti, std::to_string(uid), std::to_string(exp), ip});
  if (!s.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  json claims = {{"iss", "zt-gateway"}, {"sub", std::to_string(uid)}, {"jti", jti},
                 {"role", role},        {"iat", now},                {"exp", exp}};
  audit(uid, email, std::nullopt, "login", "allow", "login_success", ip);
  send_json(res, 200, json{{"access_token", jwt_sign(claims, cfg_.jwt_secret)},
                           {"token_type", "Bearer"},
                           {"expires_in", cfg_.jwt_ttl_sec}});
}

void Gateway::h_logout(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_auth(req, res, ctx, "logout")) return;
  auto r = db_.exec("UPDATE sessions SET revoked=TRUE WHERE id=$1", {ctx.session_id});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  audit(ctx.user_id, ctx.email, std::nullopt, "logout", "allow", "session_revoked", req.remote_addr);
  send_json(res, 200, json{{"status", "logged_out"}});
}

void Gateway::h_list_resources(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_auth(req, res, ctx, "list_resources")) return;
  auto r = db_.exec(
      "SELECT r.id::text, r.name, p.require_healthy_device::text FROM resources r "
      "JOIN policies p ON p.resource_id = r.id "
      "WHERE p.active AND $1::text = ANY(p.allowed_roles) ORDER BY r.id",
      {ctx.role});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  json arr = json::array();
  for (const auto& w : r.rows)
    arr.push_back({{"id", std::stoll(w[0])}, {"name", w[1]}, {"device_required", w[2] == "true"}});
  send_json(res, 200, json{{"resources", arr}});
}

void Gateway::h_access_resource(const Req& req, Res& res) {
  const std::string ip = req.remote_addr;
  int64_t rid = 0;
  if (!parse_id(req.path_params.at("id"), rid)) throw BadRequest("invalid_id");

  // 1) Authenticate EVERY request (token + live session + live account).
  AuthCtx ctx;
  if (!require_auth(req, res, ctx, "resource_access", rid)) return;

  auto deny = [&](const std::string& reason) {
    audit(ctx.user_id, ctx.email, rid, "resource_access", "deny", reason, ip);
    send_err(res, 403, "access_denied");  // generic to the client, precise in the audit log
  };

  // 2) Load resource + policy (cached, invalidated on policy change).
  std::optional<ResourceEntry> entry;
  try {
    entry = cache_.get(rid, now_sec());
  } catch (const std::exception&) {
    audit(ctx.user_id, ctx.email, rid, "resource_access", "error", "policy_backend_unavailable", ip);
    send_err(res, 503, "service_unavailable");
    return;
  }
  if (!entry) return deny("resource_not_found");  // same 403 as "not allowed": no existence oracle

  // 3) Gather request context (device posture) and evaluate. Default deny.
  DeviceState dev;
  if (entry->policy && entry->policy->require_healthy_device) {
    std::string did = req.get_header_value("X-Device-Id");
    if (valid_device_id(did)) dev = load_device(did, ctx.user_id);
  }
  Subject subj{ctx.user_id, ctx.role, true};
  Decision d = evaluate(subj, entry->policy, dev, now_sec());
  if (!d.allow) return deny(d.reason);

  // 4) Fail closed: if we cannot record the decision, we do not grant access.
  if (!audit(ctx.user_id, ctx.email, rid, "resource_access", "allow", d.reason, ip)) {
    send_err(res, 503, "service_unavailable");
    return;
  }

  // 5) Forward. Denied requests never reach this point.
  std::string origin, path;
  if (!parse_upstream(entry->upstream_url, origin, path)) {
    audit(ctx.user_id, ctx.email, rid, "resource_access", "error", "bad_upstream_config", ip);
    send_err(res, 502, "bad_gateway");
    return;
  }
  httplib::Client cli(origin);
  cli.set_connection_timeout(2, 0);
  cli.set_read_timeout(cfg_.upstream_timeout_sec, 0);
  cli.set_write_timeout(cfg_.upstream_timeout_sec, 0);
  httplib::Headers hdrs = {{"X-ZT-User-Id", std::to_string(ctx.user_id)},
                           {"X-ZT-User-Email", ctx.email},
                           {"X-ZT-Role", ctx.role},
                           {"X-ZT-Resource", entry->name}};  // NOTE: the bearer token is NOT forwarded
  auto up = cli.Get(path, hdrs);
  if (!up) {
    metrics_.inc("zt_upstream_errors_total");
    audit(ctx.user_id, ctx.email, rid, "resource_access", "error", "upstream_unreachable", ip);
    send_err(res, 502, "bad_gateway");
    return;
  }

  // 6) Revocation while the request was in flight: re-check before releasing the response.
  AuthOutcome again = authenticate(req);
  if (again.status != AuthStatus::Ok) {
    audit(ctx.user_id, ctx.email, rid, "resource_access", "deny", "revoked_during_request", ip);
    send_err(res, 401, "unauthorized");
    return;
  }
  std::string ct = up->get_header_value("Content-Type");
  res.status = up->status;
  res.set_content(up->body, ct.empty() ? "application/octet-stream" : ct);
}

void Gateway::h_create_resource(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "create_resource")) return;
  json b = parse_body(req);
  std::string name = get_str(b, "name", 64), url = get_str(b, "upstream_url", 512);
  std::string origin, path;
  if (!valid_name(name)) throw BadRequest("invalid_name");
  if (!parse_upstream(url, origin, path)) throw BadRequest("invalid_upstream_url");
  auto r = db_.exec("INSERT INTO resources(name, upstream_url) VALUES($1,$2) RETURNING id", {name, url});
  if (!r.ok) {
    send_err(res, r.sqlstate == "23505" ? 409 : 503, r.sqlstate == "23505" ? "name_taken" : "service_unavailable");
    return;
  }
  audit(ctx.user_id, ctx.email, std::stoll(r.rows[0][0]), "create_resource", "allow", "created", req.remote_addr);
  send_json(res, 201, json{{"id", std::stoll(r.rows[0][0])}, {"name", name}});
}

void Gateway::h_upsert_policy(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "upsert_policy")) return;
  json b = parse_body(req);
  int64_t rid = get_int(b, "resource_id", 1, INT64_MAX / 2);
  if (!b.contains("allowed_roles") || !b["allowed_roles"].is_array() || b["allowed_roles"].size() > 16)
    throw BadRequest("invalid_allowed_roles");
  std::vector<std::string> roles;
  for (const auto& r : b["allowed_roles"]) {
    if (!r.is_string() || !valid_role(r.get<std::string>())) throw BadRequest("invalid_allowed_roles");
    roles.push_back(r.get<std::string>());
  }
  bool dev = get_bool(b, "require_healthy_device", true);
  int64_t age = get_int(b, "max_posture_age_sec", 30, 86400, 900);
  bool active = get_bool(b, "active", true);

  auto r = db_.exec(
      "INSERT INTO policies(resource_id,allowed_roles,require_healthy_device,max_posture_age_sec,active) "
      "VALUES($1::bigint,$2::text[],$3::boolean,$4::int,$5::boolean) "
      "ON CONFLICT (resource_id) DO UPDATE SET allowed_roles=EXCLUDED.allowed_roles, "
      "require_healthy_device=EXCLUDED.require_healthy_device, "
      "max_posture_age_sec=EXCLUDED.max_posture_age_sec, active=EXCLUDED.active, updated_at=now() "
      "RETURNING id",
      {std::to_string(rid), pg_array(roles), dev ? "true" : "false", std::to_string(age),
       active ? "true" : "false"});
  if (!r.ok) {
    if (r.sqlstate == "23503") send_err(res, 404, "resource_not_found");
    else send_err(res, 503, "service_unavailable");
    return;
  }
  cache_.invalidate(rid);  // AFTER the commit, so a concurrent reload sees the new row
  audit(ctx.user_id, ctx.email, rid, "upsert_policy", "allow", "policy_saved", req.remote_addr);
  send_json(res, 200, json{{"policy_id", std::stoll(r.rows[0][0])}, {"resource_id", rid}});
}

void Gateway::h_audit_logs(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "view_audit_logs")) return;
  int64_t limit = 100;
  if (req.has_param("limit") && (!parse_id(req.get_param_value("limit"), limit) || limit > 500))
    throw BadRequest("invalid_limit");
  std::string decision = req.get_param_value("decision");
  std::string email = lower(req.get_param_value("email"));
  std::string reason = req.get_param_value("reason");
  if (!decision.empty() && decision != "allow" && decision != "deny" && decision != "error")
    throw BadRequest("invalid_decision");
  if (email.size() > 254) throw BadRequest("invalid_email");
  static const std::regex re_reason("^[a-z_]{0,64}$");
  if (!std::regex_match(reason, re_reason)) throw BadRequest("invalid_reason");

  auto r = db_.exec(
      "SELECT id::text, extract(epoch from ts)::bigint::text, COALESCE(user_id::text,''), email, "
      "COALESCE(resource_id::text,''), action, decision, reason, ip FROM audit_logs "
      "WHERE ($1::text='' OR decision=$1::text) AND ($2::text='' OR email=$2::text) "
      "AND ($3::text='' OR reason=$3::text) ORDER BY id DESC LIMIT $4::int",
      {decision, email, reason, std::to_string(limit)});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  json arr = json::array();
  for (const auto& w : r.rows)
    arr.push_back({{"id", std::stoll(w[0])}, {"ts", std::stoll(w[1])}, {"user_id", w[2]},
                   {"email", w[3]}, {"resource_id", w[4]}, {"action", w[5]},
                   {"decision", w[6]}, {"reason", w[7]}, {"ip", w[8]}});
  send_json(res, 200, json{{"logs", arr}});
}

void Gateway::h_enroll_device(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "enroll_device")) return;
  json b = parse_body(req);
  int64_t uid = get_int(b, "user_id", 1, INT64_MAX / 2);
  std::string did = "dev-" + random_hex(8), secret = random_hex(32);
  auto r = db_.exec("INSERT INTO devices(id,user_id,secret) VALUES($1,$2::bigint,$3)",
                    {did, std::to_string(uid), secret});
  if (!r.ok) {
    send_err(res, r.sqlstate == "23503" ? 404 : 503, r.sqlstate == "23503" ? "user_not_found" : "service_unavailable");
    return;
  }
  audit(ctx.user_id, ctx.email, std::nullopt, "enroll_device", "allow", "device_enrolled", req.remote_addr);
  // The secret is shown exactly once; it simulates a key sealed inside the device agent.
  send_json(res, 201, json{{"device_id", did}, {"secret", secret}});
}

void Gateway::h_attest(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_auth(req, res, ctx, "device_attest")) return;
  const std::string ip = req.remote_addr;
  json b = parse_body(req);
  std::string did = get_str(b, "device_id", 64);
  if (!valid_device_id(did)) throw BadRequest("invalid_device_id");
  int64_t ts = get_int(b, "ts", 1, 4102444800LL);
  if (!b.contains("posture") || !b["posture"].is_object()) throw BadRequest("invalid_posture");
  const json& p = b["posture"];
  bool os = get_bool(p, "os_patched"), disk = get_bool(p, "disk_encrypted"),
       fw = get_bool(p, "firewall_on"), av = get_bool(p, "antivirus_on");
  std::string sig = get_str(b, "signature", 128);

  auto r = db_.exec("SELECT user_id::text, secret FROM devices WHERE id=$1", {did});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  if (r.rows.empty() || r.rows[0][0] != std::to_string(ctx.user_id)) {
    audit(ctx.user_id, ctx.email, std::nullopt, "device_attest", "deny", "device_unknown_or_not_owned", ip);
    send_err(res, 403, "access_denied");
    return;
  }
  int64_t now = now_sec();
  if (ts > now + 60 || now - ts > 60) {
    audit(ctx.user_id, ctx.email, std::nullopt, "device_attest", "deny", "report_clock_skew", ip);
    send_err(res, 400, "stale_timestamp");
    return;
  }
  // The client NEVER gets to just claim "I'm healthy": the report must be signed by the
  // device's enrolled key. A forged or edited report fails here.
  std::string canonical = did + "|" + std::to_string(ts) + "|" + (os ? "1" : "0") +
                          (disk ? "1" : "0") + (fw ? "1" : "0") + (av ? "1" : "0");
  if (!const_time_eq(hmac_sha256_hex(r.rows[0][1], canonical), sig)) {
    audit(ctx.user_id, ctx.email, std::nullopt, "device_attest", "deny", "bad_signature", ip);
    send_err(res, 403, "access_denied");
    return;
  }
  const bool healthy = os && disk && fw && av;
  json details = {{"os_patched", os}, {"disk_encrypted", disk}, {"firewall_on", fw}, {"antivirus_on", av}};
  auto u = db_.exec(
      "INSERT INTO device_status(device_id,user_id,healthy,details,last_report_ts,last_check) "
      "VALUES($1,$2::bigint,$3::boolean,$4::jsonb,$5::bigint,now()) "
      "ON CONFLICT (device_id) DO UPDATE SET healthy=EXCLUDED.healthy, details=EXCLUDED.details, "
      "last_report_ts=EXCLUDED.last_report_ts, last_check=now() "
      "WHERE device_status.last_report_ts < EXCLUDED.last_report_ts",
      {did, std::to_string(ctx.user_id), healthy ? "true" : "false", details.dump(), std::to_string(ts)});
  if (!u.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  if (u.affected == 0) {  // same-or-older timestamp than the last accepted report => replay
    audit(ctx.user_id, ctx.email, std::nullopt, "device_attest", "deny", "replayed_report", ip);
    send_err(res, 409, "replayed_report");
    return;
  }
  audit(ctx.user_id, ctx.email, std::nullopt, "device_attest", "allow",
        healthy ? "posture_healthy" : "posture_unhealthy", ip);
  send_json(res, 200, json{{"device_id", did}, {"healthy", healthy}});
}

void Gateway::h_user_status(const Req& req, Res& res, bool active) {
  AuthCtx ctx;
  const char* action = active ? "enable_user" : "disable_user";
  if (!require_admin(req, res, ctx, action)) return;
  int64_t uid = 0;
  if (!parse_id(req.path_params.at("id"), uid)) throw BadRequest("invalid_id");
  if (!active && uid == ctx.user_id) throw BadRequest("cannot_disable_self");
  // One statement => atomic: disabling an account and killing its sessions cannot be split.
  auto r = db_.exec(
      "WITH u AS (UPDATE users SET active=$2::boolean WHERE id=$1::bigint RETURNING id), "
      "s AS (UPDATE sessions SET revoked=TRUE WHERE $2::boolean = FALSE AND user_id IN (SELECT id FROM u)) "
      "SELECT id FROM u",
      {std::to_string(uid), active ? "true" : "false"});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  if (r.rows.empty()) {
    send_err(res, 404, "user_not_found");
    return;
  }
  audit(ctx.user_id, ctx.email, std::nullopt, action, "allow", "user_" + std::to_string(uid), req.remote_addr);
  send_json(res, 200, json{{"user_id", uid}, {"active", active}});
}

void Gateway::h_user_role(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "set_role")) return;
  int64_t uid = 0;
  if (!parse_id(req.path_params.at("id"), uid)) throw BadRequest("invalid_id");
  json b = parse_body(req);
  std::string role = get_str(b, "role", 32);
  if (!valid_role(role)) throw BadRequest("invalid_role");
  auto r = db_.exec("UPDATE users SET role=$2 WHERE id=$1::bigint RETURNING id", {std::to_string(uid), role});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  if (r.rows.empty()) {
    send_err(res, 404, "user_not_found");
    return;
  }
  audit(ctx.user_id, ctx.email, std::nullopt, "set_role", "allow", "user_" + std::to_string(uid) + "_" + role, req.remote_addr);
  send_json(res, 200, json{{"user_id", uid}, {"role", role}});  // effective on the very next request
}

void Gateway::h_revoke_sessions(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "revoke_sessions")) return;
  int64_t uid = 0;
  if (!parse_id(req.path_params.at("id"), uid)) throw BadRequest("invalid_id");
  auto r = db_.exec("UPDATE sessions SET revoked=TRUE WHERE user_id=$1::bigint AND NOT revoked", {std::to_string(uid)});
  if (!r.ok) {
    send_err(res, 503, "service_unavailable");
    return;
  }
  audit(ctx.user_id, ctx.email, std::nullopt, "revoke_sessions", "allow", "user_" + std::to_string(uid), req.remote_addr);
  send_json(res, 200, json{{"user_id", uid}, {"revoked", r.affected}});
}

void Gateway::h_metrics(const Req& req, Res& res) {
  AuthCtx ctx;
  if (!require_admin(req, res, ctx, "view_metrics")) return;
  res.status = 200;
  res.set_content(metrics_.render({{"zt_policy_cache_hits_total", static_cast<double>(cache_.hits())},
                                   {"zt_policy_cache_misses_total", static_cast<double>(cache_.misses())}}),
                  "text/plain; version=0.0.4");
}

}  // namespace zt
