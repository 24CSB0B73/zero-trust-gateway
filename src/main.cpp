#include <chrono>
#include <csignal>
#include <iostream>
#include <memory>
#include <thread>

#include "gateway.hpp"

static zt::Gateway* g_gw = nullptr;
static void on_signal(int) {
  if (g_gw) g_gw->stop();
}

int main() {
  try {
    zt::Config cfg = zt::Config::from_env();
    std::unique_ptr<zt::Gateway> gw;
    for (int i = 1; i <= 30 && !gw; ++i) {  // wait for PostgreSQL (useful under docker compose)
      try {
        gw = std::make_unique<zt::Gateway>(cfg);
      } catch (const std::exception& e) {
        std::cerr << "[startup] " << e.what() << " (attempt " << i << "/30)" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(1));
      }
    }
    if (!gw) return 1;
    gw->bootstrap();
    g_gw = gw.get();
    std::signal(SIGINT, on_signal);
    std::signal(SIGTERM, on_signal);
    return gw->run();
  } catch (const std::exception& e) {
    std::cerr << "fatal: " << e.what() << std::endl;
    return 1;
  }
}
