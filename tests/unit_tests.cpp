#include <gtest/gtest.h>

#include <atomic>
#include <thread>
#include <vector>

#include "crypto.hpp"
#include "limits.hpp"
#include "policy.hpp"

using namespace zt;
using nlohmann::json;

// ----------------------------------------------------------------- passwords
TEST(Password, HashVerifyRoundTrip) {
  auto h = hash_password("correct horse battery", 1000);
  EXPECT_TRUE(verify_password("correct horse battery", h));
  EXPECT_FALSE(verify_password("wrong password", h));
}
TEST(Password, SaltedHashesDiffer) {
  EXPECT_NE(hash_password("same-password-1", 1000), hash_password("same-password-1", 1000));
}
TEST(Password, MalformedStoredHashRejected) {
  EXPECT_FALSE(verify_password("x", ""));
  EXPECT_FALSE(verify_password("x", "plaintext"));
  EXPECT_FALSE(verify_password("x", "pbkdf2_sha256$abc$zz$zz"));
}

// ----------------------------------------------------------------- JWT
static const std::string kSecret = "unit-test-secret-unit-test-secret-1234";
static json claims(int64_t exp) {
  return {{"iss", "zt-gateway"}, {"sub", "7"}, {"jti", "abc"}, {"exp", exp}};
}
TEST(Jwt, ValidTokenAccepted) {
  json out;
  auto t = jwt_sign(claims(now_sec() + 60), kSecret);
  EXPECT_EQ(jwt_verify(t, kSecret, out), JwtStatus::Ok);
  EXPECT_EQ(out["sub"], "7");
}
TEST(Jwt, ExpiredRejected) {
  json out;
  EXPECT_EQ(jwt_verify(jwt_sign(claims(now_sec() - 1), kSecret), kSecret, out), JwtStatus::Expired);
}
TEST(Jwt, WrongSecretRejected) {
  json out;
  auto t = jwt_sign(claims(now_sec() + 60), "another-secret-another-secret-123456");
  EXPECT_EQ(jwt_verify(t, kSecret, out), JwtStatus::BadSignature);
}
TEST(Jwt, TamperedPayloadRejected) {
  json out;
  auto t = jwt_sign(claims(now_sec() + 60), kSecret);
  size_t d1 = t.find('.'), d2 = t.find('.', d1 + 1);
  json evil = claims(now_sec() + 60);
  evil["sub"] = "1";  // try to become user 1 (admin)
  std::string forged = t.substr(0, d1 + 1) + b64url_encode(evil.dump()) + t.substr(d2);
  EXPECT_EQ(jwt_verify(forged, kSecret, out), JwtStatus::BadSignature);
}
TEST(Jwt, AlgNoneRejected) {
  json out;
  std::string t = b64url_encode(R"({"alg":"none","typ":"JWT"})") + "." +
                  b64url_encode(claims(now_sec() + 60).dump()) + ".";
  EXPECT_NE(jwt_verify(t, kSecret, out), JwtStatus::Ok);
}
TEST(Jwt, GarbageRejected) {
  json out;
  for (std::string g : {"", "a", "a.b", "a.b.c.d", "...", "!!!.@@@.###"})
    EXPECT_NE(jwt_verify(g, kSecret, out), JwtStatus::Ok) << g;
}
TEST(Crypto, Base64UrlRoundTrip) {
  for (size_t n = 0; n < 40; ++n) {
    std::string s = random_bytes(n), back;
    ASSERT_TRUE(b64url_decode(b64url_encode(s), back));
    EXPECT_EQ(s, back);
  }
}

// ----------------------------------------------------------------- policy engine
static Policy pol(std::vector<std::string> roles, bool dev = true, bool active = true) {
  Policy p;
  p.allowed_roles = std::move(roles);
  p.require_healthy_device = dev;
  p.active = active;
  p.max_posture_age_sec = 900;
  return p;
}
static DeviceState good_device(int64_t now) { return DeviceState{true, true, true, now - 10}; }

TEST(PolicyEngine, AllowsWhenEverythingMatches) {
  auto d = evaluate({1, "employee", true}, pol({"employee"}), good_device(1000), 1000);
  EXPECT_TRUE(d.allow);
}
TEST(PolicyEngine, DefaultDenyWithoutPolicy) {
  auto d = evaluate({1, "admin", true}, std::nullopt, good_device(1000), 1000);
  EXPECT_FALSE(d.allow);
  EXPECT_EQ(d.reason, "no_policy");
}
TEST(PolicyEngine, DisabledAccountDenied) {
  EXPECT_EQ(evaluate({1, "employee", false}, pol({"employee"}), good_device(1000), 1000).reason, "account_disabled");
}
TEST(PolicyEngine, InactivePolicyDenied) {
  EXPECT_EQ(evaluate({1, "employee", true}, pol({"employee"}, true, false), good_device(1000), 1000).reason, "policy_inactive");
}
TEST(PolicyEngine, WrongRoleDeniedEvenWithPerfectDevice) {
  auto d = evaluate({1, "contractor", true}, pol({"admin"}), good_device(1000), 1000);
  EXPECT_FALSE(d.allow);
  EXPECT_EQ(d.reason, "role_not_permitted");
}
TEST(PolicyEngine, EmptyRoleListDeniesEveryone) {
  EXPECT_FALSE(evaluate({1, "admin", true}, pol({}), good_device(1000), 1000).allow);
}
TEST(PolicyEngine, DeviceRules) {
  Subject s{1, "employee", true};
  auto p = pol({"employee"});
  EXPECT_EQ(evaluate(s, p, DeviceState{}, 1000).reason, "device_missing");
  EXPECT_EQ(evaluate(s, p, DeviceState{true, false, true, 990}, 1000).reason, "device_not_owned");
  EXPECT_EQ(evaluate(s, p, DeviceState{true, true, false, 990}, 1000).reason, "device_unhealthy");
  EXPECT_EQ(evaluate(s, p, DeviceState{true, true, true, 1000 - 901}, 1000).reason, "device_posture_stale");
  EXPECT_TRUE(evaluate(s, p, DeviceState{true, true, true, 1000 - 900}, 1000).allow);
}
TEST(PolicyEngine, DeviceIgnoredWhenNotRequired) {
  EXPECT_TRUE(evaluate({1, "employee", true}, pol({"employee"}, false), DeviceState{}, 1000).allow);
}

// ----------------------------------------------------------------- policy cache
static ResourceEntry entry(int64_t id) {
  ResourceEntry e;
  e.id = id;
  e.name = "r" + std::to_string(id);
  e.policy = pol({"employee"});
  return e;
}
TEST(PolicyCache, HitMissAndTtl) {
  std::atomic<int> loads{0};
  PolicyCache c([&](int64_t id) { loads++; return std::optional<ResourceEntry>(entry(id)); }, 30);
  c.get(1, 100);
  c.get(1, 110);
  EXPECT_EQ(loads, 1);
  c.get(1, 131);  // TTL expired
  EXPECT_EQ(loads, 2);
}
TEST(PolicyCache, InvalidateForcesReload) {
  std::atomic<int> loads{0};
  PolicyCache c([&](int64_t id) { loads++; return std::optional<ResourceEntry>(entry(id)); }, 300);
  c.get(1, 100);
  c.invalidate(1);
  c.get(1, 101);
  EXPECT_EQ(loads, 2);
}
TEST(PolicyCache, NotFoundIsNotCached) {
  std::atomic<int> loads{0};
  PolicyCache c([&](int64_t) { loads++; return std::optional<ResourceEntry>(); }, 300);
  EXPECT_FALSE(c.get(9, 100));
  EXPECT_FALSE(c.get(9, 101));
  EXPECT_EQ(loads, 2);
}
TEST(PolicyCache, InvalidationDuringSlowLoadPreventsStaleWriteBack) {
  PolicyCache* cp = nullptr;
  std::atomic<int> loads{0};
  PolicyCache c(
      [&](int64_t id) {
        auto e = entry(id);
        if (loads++ == 0) cp->invalidate(id);  // admin changes the policy mid-load
        return std::optional<ResourceEntry>(e);
      },
      300);
  cp = &c;
  c.get(1, 100);  // loaded the OLD data; must NOT be cached
  c.get(1, 101);
  EXPECT_EQ(loads, 2);  // second call had to reload
}
TEST(PolicyCache, ConcurrentReadersAndInvalidators) {
  PolicyCache c([](int64_t id) { return std::optional<ResourceEntry>(entry(id)); }, 300);
  std::atomic<bool> stop{false};
  std::vector<std::thread> ts;
  for (int i = 0; i < 8; ++i)
    ts.emplace_back([&] { while (!stop) ASSERT_TRUE(c.get(1 + (rand() % 4), now_sec()).has_value()); });
  for (int i = 0; i < 2; ++i)
    ts.emplace_back([&] { while (!stop) c.invalidate(1 + (rand() % 4)); });
  std::this_thread::sleep_for(std::chrono::milliseconds(300));
  stop = true;
  for (auto& t : ts) t.join();
  SUCCEED();  // the real assertion is "no crash / no TSAN report"
}

// ----------------------------------------------------------------- limiters
TEST(RateLimiter, BurstThenBlockThenRefill) {
  RateLimiter rl(3, 1);  // burst 3, +1/sec
  double t = 1000;
  EXPECT_TRUE(rl.allow("a", t));
  EXPECT_TRUE(rl.allow("a", t));
  EXPECT_TRUE(rl.allow("a", t));
  EXPECT_FALSE(rl.allow("a", t));
  EXPECT_TRUE(rl.allow("b", t));          // other keys unaffected
  EXPECT_TRUE(rl.allow("a", t + 1.01));   // refilled one token
  EXPECT_FALSE(rl.allow("a", t + 1.02));
}
TEST(RateLimiter, ThreadSafeNeverExceedsCapacity) {
  RateLimiter rl(100, 0.0001);
  std::atomic<int> ok{0};
  std::vector<std::thread> ts;
  for (int i = 0; i < 8; ++i)
    ts.emplace_back([&] { for (int j = 0; j < 100; ++j) if (rl.allow("k")) ok++; });
  for (auto& t : ts) t.join();
  EXPECT_EQ(ok, 100);
}
TEST(LoginThrottle, LocksAfterNFailuresAndUnlocks) {
  LoginThrottle lt(3, 60, 120);
  EXPECT_EQ(lt.blocked_for("u", 0), 0);
  lt.record_failure("u", 0);
  lt.record_failure("u", 1);
  EXPECT_EQ(lt.blocked_for("u", 2), 0);
  lt.record_failure("u", 2);
  EXPECT_GT(lt.blocked_for("u", 3), 0);
  EXPECT_EQ(lt.blocked_for("u", 123), 0);
}
TEST(LoginThrottle, SuccessResets) {
  LoginThrottle lt(3, 60, 120);
  lt.record_failure("u", 0);
  lt.record_failure("u", 1);
  lt.record_success("u");
  lt.record_failure("u", 2);
  EXPECT_EQ(lt.blocked_for("u", 3), 0);
}
