class FakeRegistry {
 public:
  FakeRegistry(const std::string& auth_url, const std::string& base_url, const boost::filesystem::path& root_dir) :
      auth_url_{auth_url}, base_url_{base_url}, root_dir_{root_dir}
  { }

  using ManifestPostProcessor = std::function<void(Json::Value&, std::string&)>;

  std::string addApp(const std::string& app_repo, const std::string& app_name,
                     ManifestPostProcessor manifest_post_processor = nullptr,
                     const std::string file_name = Docker::ComposeAppEngine::ComposeFile,
                     std::string app_content = "some fake content qwertyuiop 1231313123123123") {
    auto docker_file = root_dir_ / app_name / file_name;
    Utils::writeFile(docker_file, app_content);

    tgz_path_ = root_dir_ / app_name / (app_name + ".tgz");
    std::string stdout_msg;
    boost::process::system("tar -czf " + tgz_path_.string() + " " + file_name, boost::process::start_dir = (root_dir_ / app_name));
    std::string tgz_content = Utils::readFile(tgz_path_);
    auto hash = boost::algorithm::to_lower_copy(boost::algorithm::hex(Crypto::sha256digest(tgz_content)));
    // TODO: it should be in ComposeAppEngine::Manifest::Manifest()
    manifest_.clear();
    manifest_["annotations"]["compose-app"] = "v1";
    manifest_["layers"][0]["digest"] = "sha256:" + hash;
    manifest_["layers"][0]["size"] = tgz_content.size();
    manifest_hash_ = boost::algorithm::to_lower_copy(boost::algorithm::hex(Crypto::sha256digest(Utils::jsonToCanonicalStr(manifest_))));
    if (manifest_post_processor) {
      manifest_post_processor(manifest_, hash);
      manifest_hash_ = boost::algorithm::to_lower_copy(boost::algorithm::hex(Crypto::sha256digest(Utils::jsonToCanonicalStr(manifest_))));
    }
    archive_name_ = hash.substr(0, 7) + '.' + app_name + ".tgz";

    // app URI
    auto app_uri = base_url_ + '/' + app_repo + '/' + app_name + '@' + "sha256:" + manifest_hash_;

    // create a valid docker-compose.yaml (single service)
    auto compose_file = root_dir_ / "compose-apps" / app_name / file_name;
    const std::string yaml("services:\n  "+ app_name + ":\n    labels:\n      io.compose-spec.config-hash: " + manifest_hash_ + "\nversion: " +R"("3.2")");
    Utils::writeFile(compose_file, yaml);

    return app_uri;
  }

  const std::string& authURL() const { return auth_url_; }
  const std::string& baseURL() const { return base_url_; }
  Json::Value& manifest() { return manifest_; }
  const std::string& archiveName() const { return archive_name_; }
  std::string getManifest() const { was_manifest_requested_ = true;
    return Utils::jsonToCanonicalStr(manifest_); }
  std::string getShortManifestHash() const { return manifest_hash_.substr(0, 7); }
  std::string getArchiveContent() const { return Utils::readFile(tgz_path_); }

  bool wasManifestRequested() const { return was_manifest_requested_; }

 private:
  const std::string auth_url_;
  const std::string base_url_;
  boost::filesystem::path root_dir_;
  Json::Value manifest_;
  std::string manifest_hash_;
  boost::filesystem::path tgz_path_;
  std::string archive_name_;
  mutable bool was_manifest_requested_{false};
};


