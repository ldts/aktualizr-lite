class DeviceGatewayMock {
 public:
  static std::string RunCmd;

 public:
  DeviceGatewayMock(const OSTreeRepoMock& ostree, const TufRepoMock& tuf)
      : ostree_{ostree},
        tuf_{tuf},
        port_{TestUtils::getFreePort()},
        url_{"http://localhost:" + port_},
        req_headers_file_{tuf_.getPath() + "/headers.json"},
        process_{RunCmd,           "--port",         port_, "--ostree", ostree_.getPath(), "--tuf-repo", tuf_.getPath(),
    "--headers-file", req_headers_file_}
  {
    TestUtils::waitForServer(url_ + "/");
    LOG_INFO << "Device Gateway is running on port " << port_;
  }

  ~DeviceGatewayMock() {
    process_.terminate();
    process_.wait_for(std::chrono::seconds(10));
  }

 public:
  std::string getOsTreeUri() const { return url_ + "/treehub"; }
  std::string getTufRepoUri() const { return url_ + "/repo"; }
  const std::string& getPort() const { return port_; }
  Json::Value getReqHeaders() const { return Utils::parseJSONFile(req_headers_file_); }

 private:
  const OSTreeRepoMock& ostree_;
  const TufRepoMock& tuf_;
  const std::string port_;
  const std::string url_;
  const std::string req_headers_file_;
  boost::process::child process_;
};

std::string DeviceGatewayMock::RunCmd;
