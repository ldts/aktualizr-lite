static std::string executeCmd(const std::string& cmd, const std::vector<std::string>& args, const std::string& desc) {
  auto res = Process::spawn(cmd, args);
  if (std::get<0>(res) != 0) throw std::runtime_error("Failed to " + desc + ": " + std::get<2>(res));

  auto std_out = std::get<1>(res);
  boost::trim_right_if(std_out, boost::is_any_of(" \t\r\n"));
  return std_out;
}

#include "mocks/appengine.cc"
#include "mocks/sysrootfs.cc"
#include "mocks/ostreerepo.cc"
#include "mocks/sysostreerepo.cc"
#include "mocks/tufrepo.cc"
#include "mocks/devicegateway.cc"
#include "mocks/fakeregistry.cc"
#include "mocks/fakeotaclient.cc"

class LiteClientTest : public ::testing::Test {
 public:
  static std::string SysRootSrc;

 protected:
  LiteClientTest()
      : sys_rootfs_{(test_dir_.Path() / "sysroot-fs").string(), branch, hw_id, os},
        sys_repo_{(test_dir_.Path() / "sysrepo").string(), os},
        tuf_repo_{test_dir_.Path() / "repo"},
        ostree_repo_{(test_dir_.Path() / "treehub").string(), true},
        device_gateway_{ostree_repo_, tuf_repo_},
        initial_target_{Uptane::Target::Unknown()},
        sysroot_hash_{sys_repo_.getRepo().commit(sys_rootfs_.path, sys_rootfs_.branch)}
  {
    sys_repo_.deploy(sysroot_hash_);
  }

  enum class InitialVersion {kOff, kOn, kCorrupted1, kCorrupted2 };

  /**
   * method createLiteClient
   */
  std::shared_ptr<LiteClient> createLiteClient(InitialVersion initial_version = InitialVersion::kOn,
                                               boost::optional<std::vector<std::string>> apps = boost::none) {
    Config conf;
    conf.uptane.repo_server = "http://localhost:" + device_gateway_.getPort() + "/repo";
    conf.provision.primary_ecu_hardware_id = hw_id;
    conf.storage.path = test_dir_.Path();

    conf.pacman.type = ComposeAppManager::Name;
    conf.pacman.sysroot = sys_repo_.getPath();
    conf.pacman.os = os;
    conf.pacman.extra["booted"] = "0";
    conf.pacman.extra["compose_apps_root"] = (test_dir_.Path() / "compose-apps").string();
    if (!!apps) {
      conf.pacman.extra["compose_apps"] = boost::algorithm::join(*apps, ",");
    }
    conf.pacman.extra["docker_compose_bin"] = "tests/compose_fake.sh";
    boost::filesystem::copy("tests/docker_fake.sh", test_dir_.Path()/ "docker_fake.sh");
    conf.pacman.extra["docker_bin"] = (test_dir_.Path() / "docker_fake.sh").string();
    conf.pacman.extra["docker_prune"] = "0";

    app_shortlist_ = apps;
    conf.pacman.ostree_server = "https://localhost:" + device_gateway_.getPort() + "/treehub";

    conf.bootloader.reboot_command = "/bin/true";
    conf.bootloader.reboot_sentinel_dir = conf.storage.path;
    conf.import.base_path = test_dir_ / "import";

    if (initial_version == InitialVersion::kOn || initial_version == InitialVersion::kCorrupted1 ||
        initial_version == InitialVersion::kCorrupted2) {
      /*
       * Sample LMP/OE generated installed_version file
       *
       * {
       *   "raspberrypi4-64-lmp" {
       *      "hashes": {
       *        "sha256": "cbf23f479964f512ff1d0b01a688d096a670d1d099c1ee3d46baea203e7ef4ab"
       *      },
       *      "is_current": true,
       *      "custom": {
       *        "targetFormat": "OSTREE",
       *        "name": "raspberrypi4-64-lmp",
       *        "version": "1",
       *        "hardwareIds": [
       *                       "raspberrypi4-64"
       *                       ],
       *        "lmp-manifest-sha": "0db09a7e9bac87ef2127e5be8d11f23b3e18513c",
       *        "arch": "aarch64",
       *        "image-file": "lmp-factory-image-raspberrypi4-64.wic.gz",
       *        "meta-subscriber-overrides-sha": "43093be20fa232ef5fe17135115bac4327b501bd",
       *        "tags": [
       *                "master"
       *                ],
       *        "docker_compose_apps": {
       *          "app-01": {
       *            "uri":
       * "hub.foundries.io/msul-dev01/app-06@sha256:2e7b8bc87c67f6042fb88e575a1c73bf70d114f3f2fd1a7aeb3d1bf3b6a0737f"
       *          },
       *          "app-02": {
       *            "uri":
       * "hub.foundries.io/msul-dev01/app-05@sha256:267b14e2e0e98d7e966dbd49bddaa792e5d07169eb3cf2462bbbfecac00f46ef"
       *          }
       *        },
       *        "containers-sha": "a041e7a0aa1a8e73a875b4c3fdf9a418d3927894"
       *     }
       *  }
       */

      Json::Value installed_version;
      // corrupted1 will invalidate the sysroot_hash_ sha256
      installed_version["hashes"]["sha256"] =
          sysroot_hash_ + (initial_version == InitialVersion::kCorrupted1 ? "DEADBEEF" : "");
      installed_version["is_current"] = true;
      installed_version["custom"]["name"] = hw_id + "-" + os;
      installed_version["custom"]["version"] = "1";
      installed_version["custom"]["hardwareIds"] = hw_id;
      installed_version["custom"]["targetFormat"] = "OSTREE";
      installed_version["custom"]["arch"] = "aarch64";
      installed_version["custom"]["image-file"] = "lmp-factory-image-raspberrypi4-64.wic.gz";
      installed_version["custom"]["tags"] = "master";

      /* create the initial_target from the above json file: pass the root node
       * name as a parameter
       */
      initial_target_ = Uptane::Target{hw_id + "-" + os + "-" + "1", installed_version};

      Json::Value ins_ver;
      // set the root node name
      ins_ver[initial_target_.filename()] = installed_version;
      // write the json information to a file (corrupted2 will write a corrupted  file)
      Utils::writeFile(conf.import.base_path / "installed_versions",
                       (initial_version == InitialVersion::kCorrupted2) ? "deadbeef\t\ncorrupted file\n\n"
                       : Utils::jsonToCanonicalStr(ins_ver),
                       true);

      getTufRepo().addTarget(initial_target_.filename(), initial_target_.sha256Hash(), hw_id, "1");
    }

    FakeRegistry* registry = new FakeRegistry("https://localhost:" + device_gateway_.getPort()+ "/hub-creds/",
                                              "https://localhost:" + device_gateway_.getPort(),
                                              test_dir_.Path());

    http_client_ = std::make_shared<FakeOtaClient>(registry);

    Docker::RegistryClient::HttpClientFactory registry_http_client_factory = [registry](const std::vector<std::string>* headers) {
      return std::make_shared<FakeOtaClient>(registry, nullptr);
    };

    ComposeAppManager::Config pacman_cfg{conf.pacman};
    app_engine_ = std::make_shared<Docker::ComposeAppEngine>(pacman_cfg.apps_root,
                                                             boost::filesystem::canonical(pacman_cfg.compose_bin).string() + " ",
                                                             new Docker::DockerClientIF(),
                                                             std::make_shared<Docker::RegistryClient>(conf.pacman.ostree_server, http_client_, registry_http_client_factory));
    return std::make_shared<LiteClient>(conf, app_engine_);
    }

  /**
   * method createTarget
   */
  Uptane::Target createTarget(const std::vector<AppEngine::App>* apps = nullptr) {
    const auto& latest_target{getTufRepo().getLatest()};
    std::string version;
    try {
      version = std::to_string(std::stoi(latest_target.custom_version()) + 1);
    } catch (...) {
      LOG_INFO << "No target available, preparing the first version";
      version = "1";
    }

    // update rootfs and commit it into Treehub's repo
    const std::string unique_content = Utils::randomUuid();
    const std::string unique_file = Utils::randomUuid();
    Utils::writeFile(getSysRootFs().path + "/" + unique_file, unique_content, true);
    auto hash = getOsTreeRepo().commit(getSysRootFs().path, "lmp");

    Json::Value apps_json;
    if (apps) {
      for (const auto& app :*apps) {
        apps_json[app.name]["uri"] = app.uri;
      }
    }

    // add new target to TUF repo
    const std::string name = hw_id + "-" + os + "-" + version;
    return getTufRepo().addTarget(name, hash, hw_id, version, apps_json);
  }

  /**
   * method createAppTarget
   */
  Uptane::Target createAppTarget(const std::vector<AppEngine::App>& apps) {
    const auto& latest{getTufRepo().getLatest()};
    const std::string version = std::to_string(std::stoi(latest.custom_version()) + 1);
    Json::Value apps_json;
    for (const auto& app : apps) {
      apps_json[app.name]["uri"] = app.uri;
    }

    // add new target to TUF repo
    const std::string name = hw_id + "-" + os + "-" + version;
    return getTufRepo().addTarget(name, latest.sha256Hash(), hw_id, version, apps_json);
  }

  /**
   * method createApp
   */
  AppEngine::App createApp(const std::string& name, const std::string& factory = "test-factory") {
    const std::string uri = http_client_->getRegistry()->addApp(factory, name);
    return { name, uri };
  }

  /**
   * mehod update
   */
  void update(LiteClient& client, const Uptane::Target& from, const Uptane::Target& to) {
    // TODO: remove it once aklite is moved to the newer version of LiteClient that exposes update() method
    ASSERT_TRUE(client.checkForUpdates());

    // TODO: call client->getTarget() once the method is moved to LiteClient
    ASSERT_EQ(client.download(to, ""), data::ResultCode::Numeric::kOk);
    ASSERT_EQ(client.install(to), data::ResultCode::Numeric::kNeedCompletion);

    // make sure that the new Target hasn't been applied/finalized before reboot
    ASSERT_EQ(client.getCurrent().sha256Hash(), from.sha256Hash());
    ASSERT_EQ(client.getCurrent().filename(), from.filename());
    checkHeaders(client, from);
  }

  /**
   * method updateApps
   */
  void updateApps(LiteClient& client, const Uptane::Target& from, const Uptane::Target& to,
                  data::ResultCode::Numeric expected_download_code = data::ResultCode::Numeric::kOk,
                  data::ResultCode::Numeric expected_install_code = data::ResultCode::Numeric::kOk) {
    // TODO: remove it once aklite is moved to the newer version of LiteClient that exposes update() method
    ASSERT_TRUE(client.checkForUpdates());

    // TODO: call client->getTarget() once the method is moved to LiteClient
    ASSERT_EQ(client.download(to, ""), expected_download_code);

    if (expected_download_code != data::ResultCode::Numeric::kOk) {
      ASSERT_EQ(client.getCurrent().sha256Hash(), from.sha256Hash());
      ASSERT_EQ(client.getCurrent().filename(), from.filename());
      checkHeaders(client, from);
      return;
    }

    ASSERT_EQ(client.install(to), expected_install_code);
    if (expected_install_code == data::ResultCode::Numeric::kOk) {
      // make sure that the new Target has been applied
      ASSERT_EQ(client.getCurrent().sha256Hash(), to.sha256Hash());
      ASSERT_EQ(client.getCurrent().filename(), to.filename());
      // TODO: the daemon_main is emulated,
      // see
      // https://github.com/foundriesio/aktualizr-lite/blob/7ab6998920d57605601eda16f9bebedf00cc1f7f/src/main.cc#L264
      // once the daemon_main is "cleaned" the updateHeader can be removed from the test.
      LiteClient::update_request_headers(client.http_client, to, client.config.pacman);
      checkHeaders(client, to);
    } else {
      ASSERT_EQ(client.getCurrent().sha256Hash(), from.sha256Hash());
      ASSERT_EQ(client.getCurrent().filename(), from.filename());
      checkHeaders(client, from);
    }
  }

  /**
   * method targetsMatch
   */
  bool targetsMatch(const Uptane::Target& lhs, const Uptane::Target& rhs) {
    if ((lhs.sha256Hash() != rhs.sha256Hash()) || (lhs.filename() != rhs.filename())) {
      return false;
    }

    auto lhs_custom = lhs.custom_data().get("docker_compose_apps", Json::nullValue);
    auto rhs_custom = rhs.custom_data().get("docker_compose_apps", Json::nullValue);

    if (lhs_custom == Json::nullValue && rhs_custom == Json::nullValue) {
      return true;
    }

    if ((lhs_custom != Json::nullValue && rhs_custom == Json::nullValue) ||
        (lhs_custom == Json::nullValue && rhs_custom != Json::nullValue)) {
      return false;
    }

    for (Json::ValueConstIterator app_it = lhs_custom.begin(); app_it != lhs_custom.end(); ++app_it) {
      if (!(*app_it).isObject() || !(*app_it).isMember("uri")) {
        continue;
      }

      const auto& app_name = app_it.key().asString();
      const auto& app_uri = (*app_it)["uri"].asString();
      if (!rhs_custom.isMember(app_name) || rhs_custom[app_name]["uri"] != app_uri) {
        return false;
      }
    }
    return true;
  }

  /**
   * method reboot
   */
  void reboot(std::shared_ptr<LiteClient>& client) {
    boost::filesystem::remove(test_dir_.Path() / "need_reboot");
    client = createLiteClient(InitialVersion::kOff, app_shortlist_);
  }

  /**
   * method restart
   */
  void restart(std::shared_ptr<LiteClient>& client) { client = createLiteClient(InitialVersion::kOff); }

  /**
   * method checkHeaders
   */
  void checkHeaders(LiteClient& client, const Uptane::Target& target) {
    // check for a new Target in order to send requests with headers we are interested in
    ASSERT_TRUE(client.checkForUpdates());
    if (target.MatchTarget(Uptane::Target::Unknown())) return;

    auto req_headers = getDeviceGateway().getReqHeaders();
    ASSERT_EQ(req_headers["x-ats-ostreehash"], target.sha256Hash());
    ASSERT_EQ(req_headers["x-ats-target"], target.filename());

    auto target_apps = target.custom_data()["docker_compose_apps"];
    std::vector<std::string> apps;
    for (Json::ValueIterator ii = target_apps.begin(); ii != target_apps.end(); ++ii) {
      if ((*ii).isObject() && (*ii).isMember("uri")) {
        const auto& target_app_name = ii.key().asString();
        if (!app_shortlist_ ||
            (*app_shortlist_).end() != std::find((*app_shortlist_).begin(), (*app_shortlist_).end(), target_app_name)) {
          apps.push_back(target_app_name);
        }
      }
    }

    std::string apps_list = boost::algorithm::join(apps, ",");
    ASSERT_EQ(req_headers.get("x-ats-dockerapps", ""), apps_list);
  }

  /**
   * methods: miscellaneous
   */
  void setInitialTarget(const Uptane::Target& target) { initial_target_ = target; }
  const Uptane::Target& getInitialTarget() const { return initial_target_; }

  std::shared_ptr<Docker::ComposeAppEngine>& getAppEngine() { return app_engine_; }
  SysOSTreeRepoMock& getSysRepo() { return sys_repo_; }
  DeviceGatewayMock& getDeviceGateway() { return device_gateway_; }
  SysRootFS& getSysRootFs() { return sys_rootfs_; }
  TufRepoMock& getTufRepo() { return tuf_repo_; }
  OSTreeRepoMock& getOsTreeRepo() { return ostree_repo_; }
  void setAppShortlist(const std::vector<std::string>& apps) { app_shortlist_ = boost::make_optional(apps); }

 protected:
  static const std::string branch;
  static const std::string hw_id;
  static const std::string os;

 private:
  TemporaryDirectory test_dir_;  // must be the first element in the class
  SysRootFS sys_rootfs_;
  SysOSTreeRepoMock sys_repo_;
  TufRepoMock tuf_repo_;
  OSTreeRepoMock ostree_repo_;
  DeviceGatewayMock device_gateway_;
  Uptane::Target initial_target_;
  const std::string sysroot_hash_;
  std::shared_ptr<FakeOtaClient> http_client_;
  std::shared_ptr<Docker::ComposeAppEngine> app_engine_;
  boost::optional<std::vector<std::string>> app_shortlist_;
};

std::string LiteClientTest::SysRootSrc;
const std::string LiteClientTest::branch{"lmp"};
const std::string LiteClientTest::hw_id{"raspberrypi4-64"};
const std::string LiteClientTest::os{"lmp"};
