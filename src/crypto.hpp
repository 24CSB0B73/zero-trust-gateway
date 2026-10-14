#pragma once
#include <cstdint>
#include <nlohmann/json.hpp>
#include <string>

namespace zt {

int64_t now_sec();
std::string to_hex(const std::string& raw);
bool from_hex(const std::string& hex, std::string& out);
std::string random_bytes(size_t n);
std::string random_hex(size_t nbytes);

std::string hmac_sha256_raw(const std::string& key, const std::string& data);
std::string hmac_sha256_hex(const std::string& key, const std::string& data);
bool const_time_eq(const std::string& a, const std::string& b);

std::string b64url_encode(const std::string& in);
bool b64url_decode(const std::string& in, std::string& out);

// Format: pbkdf2_sha256$<iterations>$<salt hex>$<hash hex>
std::string hash_password(const std::string& password, int iterations = 210000);
bool verify_password(const std::string& password, const std::string& stored);

// Minimal HS256 JWT. verify() rejects any alg other than HS256 (blocks "alg":"none" attacks).
enum class JwtStatus { Ok, Malformed, BadSignature, Expired, BadClaims };
std::string jwt_sign(const nlohmann::json& claims, const std::string& secret);
JwtStatus jwt_verify(const std::string& token, const std::string& secret,
                     nlohmann::json& claims_out, int64_t now = 0);

}  // namespace zt
