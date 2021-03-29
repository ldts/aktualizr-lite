class FakeOtaClient : public HttpInterface {
 public:
  FakeOtaClient(FakeRegistry* registry, const std::vector<std::string>* headers = nullptr) :
      registry_{registry}, headers_{headers}
  { }

 public:
  HttpResponse get(const std::string& url, int64_t maxsize)override {
    assert(registry_);
    std::string resp;
    if (std::string::npos != url.find(registry_->baseURL() + "/token-auth/")) {
      resp = "{\"token\":\"token\"}";
    } else if (std::string::npos != url.find(registry_->baseURL() + "/v2/")) {
      resp = registry_->getManifest();
    } else if (url == registry_->authURL()) {
      resp = "{\"Secret\":\"secret\",\"Username\":\"test-user\"}";
    } else {
      return HttpResponse(resp, 401, CURLE_OK, "");
    }
    return HttpResponse(resp, 200, CURLE_OK, "");
  }

  HttpResponse download(const std::string& url, curl_write_callback write_cb, curl_xferinfo_callback progress_cb, void* userp, curl_off_t from)override {

    (void)url;
    (void)progress_cb;
    (void)from;

    assert(registry_);
    std::string data{registry_->getArchiveContent()};
    write_cb(const_cast<char*>(data.c_str()), data.size(), 1, userp);

    return HttpResponse("resp", 200, CURLE_OK, "");
  }

  std::future<HttpResponse> downloadAsync(const std::string&, curl_write_callback, curl_xferinfo_callback, void*, curl_off_t, CurlHandler*)override {
    std::promise<HttpResponse> resp_promise;
    resp_promise.set_value(HttpResponse("", 500, CURLE_OK, ""));
    return resp_promise.get_future();
  }
  HttpResponse post(const std::string&, const std::string&, const std::string&)override { return HttpResponse("", 500, CURLE_OK, ""); }
  HttpResponse post(const std::string&, const Json::Value&)override { return HttpResponse("", 500, CURLE_OK, ""); }
  HttpResponse put(const std::string&, const std::string&, const std::string&)override { return HttpResponse("", 500, CURLE_OK, ""); }
  HttpResponse put(const std::string&, const Json::Value&)override { return HttpResponse("", 500, CURLE_OK, ""); }
  void setCerts(const std::string&, CryptoSource, const std::string&, CryptoSource, const std::string&, CryptoSource)override { }
  FakeRegistry* getRegistry() { return registry_; }

 private:
  FakeRegistry* registry_;
  const std::vector<std::string>* headers_;
};


