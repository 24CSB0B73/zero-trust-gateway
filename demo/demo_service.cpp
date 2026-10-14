// A trivial "internal application" that sits behind the gateway.
// In docker-compose it has no published port, so it is unreachable except through the gateway.
#include <httplib.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <thread>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

int main() {
  const char* p = std::getenv("PORT");
  int port = p ? std::atoi(p) : 9000;
  httplib::Server svr;
  auto app = [](const std::string& name, const std::string& secret) {
    return [name, secret](const httplib::Request& req, httplib::Response& res) {
      json j = {{"app", name},
                {"data", secret},
                {"served_to", req.get_header_value("X-ZT-User-Email")},
                {"role", req.get_header_value("X-ZT-Role")}};
      res.set_content(j.dump(), "application/json");
    };
  };
  svr.Get("/hr", app("hr-portal", "Employee records: 1,204 rows (demo)"));
  svr.Get("/finance", app("finance-reports", "Q3 revenue: $12.4M (demo)"));
  svr.Get("/wiki", app("public-wiki", "Welcome to the internal wiki (demo)"));
  svr.Get("/slow", [](const httplib::Request& req, httplib::Response& res) {  // for timeout tests
    int sec = std::atoi(req.get_param_value("sec").c_str());
    std::this_thread::sleep_for(std::chrono::seconds(std::min(std::max(sec, 0), 30)));
    res.set_content("{}", "application/json");
  });
  svr.new_task_queue = [] { return new httplib::ThreadPool(64); };
  svr.listen("0.0.0.0", port);
}
