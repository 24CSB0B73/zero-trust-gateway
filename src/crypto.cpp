#include "crypto.hpp"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <chrono>
#include <stdexcept>
#include <vector>

namespace zt {

int64_t now_sec() {
  return std::chrono::duration_cast<std::chrono::seconds>(
             std::chrono::system_clock::now().time_since_epoch())
      .count();
}

std::string to_hex(const std::string& raw) {
  static const char* d = "0123456789abcdef";
  std::string out;
  out.reserve(raw.size() * 2);
  for (unsigned char c : raw) {
    out.push_back(d[c >> 4]);
    out.push_back(d[c & 15]);
  }
  return out;
}

bool from_hex(const std::string& hex, std::string& out) {
  if (hex.size() % 2 != 0) return false;
  auto val = [](char c) -> int {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
  };
  out.clear();
  for (size_t i = 0; i < hex.size(); i += 2) {
    int hi = val(hex[i]), lo = val(hex[i + 1]);
    if (hi < 0 || lo < 0) return false;
    out.push_back(static_cast<char>((hi << 4) | lo));
  }
  return true;
}

std::string random_bytes(size_t n) {
  std::string b(n, '\0');
  if (RAND_bytes(reinterpret_cast<unsigned char*>(&b[0]), static_cast<int>(n)) != 1)
    throw std::runtime_error("RAND_bytes failed");
  return b;
}

std::string random_hex(size_t nbytes) { return to_hex(random_bytes(nbytes)); }

std::string hmac_sha256_raw(const std::string& key, const std::string& data) {
  unsigned char md[EVP_MAX_MD_SIZE];
  unsigned int len = 0;
  if (!HMAC(EVP_sha256(), key.data(), static_cast<int>(key.size()),
            reinterpret_cast<const unsigned char*>(data.data()), data.size(), md, &len))
    throw std::runtime_error("HMAC failed");
  return std::string(reinterpret_cast<char*>(md), len);
}

std::string hmac_sha256_hex(const std::string& key, const std::string& data) {
  return to_hex(hmac_sha256_raw(key, data));
}

bool const_time_eq(const std::string& a, const std::string& b) {
  if (a.size() != b.size()) return false;
  return CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
}

static const char* kB64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

std::string b64url_encode(const std::string& in) {
  std::string out;
  size_t i = 0;
  auto u = [&](size_t k) { return static_cast<uint32_t>(static_cast<unsigned char>(in[k])); };
  for (; i + 2 < in.size(); i += 3) {
    uint32_t v = (u(i) << 16) | (u(i + 1) << 8) | u(i + 2);
    out += kB64[v >> 18];
    out += kB64[(v >> 12) & 63];
    out += kB64[(v >> 6) & 63];
    out += kB64[v & 63];
  }
  if (i + 1 == in.size()) {
    uint32_t v = u(i) << 16;
    out += kB64[v >> 18];
    out += kB64[(v >> 12) & 63];
  } else if (i + 2 == in.size()) {
    uint32_t v = (u(i) << 16) | (u(i + 1) << 8);
    out += kB64[v >> 18];
    out += kB64[(v >> 12) & 63];
    out += kB64[(v >> 6) & 63];
  }
  return out;
}

bool b64url_decode(const std::string& in, std::string& out) {
  out.clear();
  uint32_t buf = 0;
  int bits = 0;
  for (char c : in) {
    int v;
    if (c >= 'A' && c <= 'Z') v = c - 'A';
    else if (c >= 'a' && c <= 'z') v = c - 'a' + 26;
    else if (c >= '0' && c <= '9') v = c - '0' + 52;
    else if (c == '-') v = 62;
    else if (c == '_') v = 63;
    else return false;
    buf = (buf << 6) | static_cast<uint32_t>(v);
    bits += 6;
    if (bits >= 8) {
      bits -= 8;
      out.push_back(static_cast<char>((buf >> bits) & 0xFF));
    }
  }
  return true;
}

static std::string pbkdf2(const std::string& pw, const std::string& salt, int iters) {
  unsigned char out[32];
  if (PKCS5_PBKDF2_HMAC(pw.data(), static_cast<int>(pw.size()),
                        reinterpret_cast<const unsigned char*>(salt.data()),
                        static_cast<int>(salt.size()), iters, EVP_sha256(), 32, out) != 1)
    throw std::runtime_error("PBKDF2 failed");
  return std::string(reinterpret_cast<char*>(out), 32);
}

std::string hash_password(const std::string& password, int iterations) {
  std::string salt = random_bytes(16);
  return "pbkdf2_sha256$" + std::to_string(iterations) + "$" + to_hex(salt) + "$" +
         to_hex(pbkdf2(password, salt, iterations));
}

bool verify_password(const std::string& password, const std::string& stored) {
  std::vector<std::string> parts;
  size_t start = 0;
  for (size_t p; (p = stored.find('$', start)) != std::string::npos; start = p + 1)
    parts.push_back(stored.substr(start, p - start));
  parts.push_back(stored.substr(start));
  if (parts.size() != 4 || parts[0] != "pbkdf2_sha256") return false;
  int iters = 0;
  try {
    iters = std::stoi(parts[1]);
  } catch (...) {
    return false;
  }
  if (iters < 1 || iters > 5000000) return false;
  std::string salt, expect;
  if (!from_hex(parts[2], salt) || !from_hex(parts[3], expect)) return false;
  return const_time_eq(pbkdf2(password, salt, iters), expect);
}

std::string jwt_sign(const nlohmann::json& claims, const std::string& secret) {
  std::string h = b64url_encode(R"({"alg":"HS256","typ":"JWT"})");
  std::string p = b64url_encode(claims.dump());
  std::string sig = b64url_encode(hmac_sha256_raw(secret, h + "." + p));
  return h + "." + p + "." + sig;
}

JwtStatus jwt_verify(const std::string& token, const std::string& secret,
                     nlohmann::json& claims_out, int64_t now) {
  if (now == 0) now = now_sec();
  size_t d1 = token.find('.');
  if (d1 == std::string::npos) return JwtStatus::Malformed;
  size_t d2 = token.find('.', d1 + 1);
  if (d2 == std::string::npos || token.find('.', d2 + 1) != std::string::npos)
    return JwtStatus::Malformed;

  std::string header_raw, payload_raw;
  if (!b64url_decode(token.substr(0, d1), header_raw)) return JwtStatus::Malformed;
  try {
    auto h = nlohmann::json::parse(header_raw);
    if (!h.is_object() || h.value("alg", "") != "HS256") return JwtStatus::BadSignature;
  } catch (...) {
    return JwtStatus::Malformed;
  }

  std::string expected = b64url_encode(hmac_sha256_raw(secret, token.substr(0, d2)));
  if (!const_time_eq(expected, token.substr(d2 + 1))) return JwtStatus::BadSignature;

  if (!b64url_decode(token.substr(d1 + 1, d2 - d1 - 1), payload_raw)) return JwtStatus::Malformed;
  try {
    auto c = nlohmann::json::parse(payload_raw);
    if (!c.is_object() || !c.contains("exp") || !c["exp"].is_number_integer())
      return JwtStatus::BadClaims;
    if (now >= c["exp"].get<int64_t>()) return JwtStatus::Expired;
    if (c.value("iss", "") != "zt-gateway") return JwtStatus::BadClaims;
    if (!c.contains("sub") || !c["sub"].is_string() || !c.contains("jti") || !c["jti"].is_string())
      return JwtStatus::BadClaims;
    claims_out = std::move(c);
  } catch (...) {
    return JwtStatus::Malformed;
  }
  return JwtStatus::Ok;
}

}  // namespace zt
