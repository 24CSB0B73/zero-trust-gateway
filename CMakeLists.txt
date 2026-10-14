cmake_minimum_required(VERSION 3.20)
project(zero_trust_gateway LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

option(ZT_BUILD_TESTS "Build GoogleTest unit tests" ON)
set(ZT_SANITIZE "" CACHE STRING "Sanitizer: thread | address | undefined | (empty)")

add_compile_options(-Wall -Wextra -Wpedantic)
if(ZT_SANITIZE)
  add_compile_options(-fsanitize=${ZT_SANITIZE} -fno-omit-frame-pointer -g)
  add_link_options(-fsanitize=${ZT_SANITIZE})
endif()

find_package(Threads REQUIRED)
find_package(OpenSSL REQUIRED)
find_package(PostgreSQL REQUIRED)

include(FetchContent)
if(POLICY CMP0135)
  cmake_policy(SET CMP0135 NEW)
endif()
FetchContent_Declare(httplib
  URL https://github.com/yhirose/cpp-httplib/archive/refs/tags/v0.18.0.tar.gz)
FetchContent_Declare(json
  URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz)
FetchContent_MakeAvailable(httplib json)

# Core library: everything except main(), so tests can link it.
add_library(zt_core STATIC
  src/crypto.cpp
  src/db.cpp
  src/policy.cpp
  src/gateway.cpp)
target_include_directories(zt_core PUBLIC src)
target_link_libraries(zt_core PUBLIC
  httplib::httplib nlohmann_json::nlohmann_json
  OpenSSL::SSL OpenSSL::Crypto PostgreSQL::PostgreSQL Threads::Threads)

add_executable(gateway src/main.cpp)
target_link_libraries(gateway PRIVATE zt_core)

add_executable(demo_service demo/demo_service.cpp)
target_link_libraries(demo_service PRIVATE httplib::httplib nlohmann_json::nlohmann_json Threads::Threads)

if(ZT_BUILD_TESTS)
  FetchContent_Declare(googletest
    URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip)
  set(INSTALL_GTEST OFF CACHE BOOL "" FORCE)
  FetchContent_MakeAvailable(googletest)
  enable_testing()
  add_executable(unit_tests tests/unit_tests.cpp)
  target_link_libraries(unit_tests PRIVATE zt_core GTest::gtest_main)
  include(GoogleTest)
  gtest_discover_tests(unit_tests)
endif()
