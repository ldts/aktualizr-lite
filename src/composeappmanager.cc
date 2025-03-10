#include "composeappmanager.h"
#include "bootloader/bootloaderlite.h"
#include "target.h"

ComposeAppManager::Config::Config(const PackageConfig& pconfig) {
  const std::map<std::string, std::string> raw = pconfig.extra;

  if (raw.count("compose_apps") == 1) {
    std::string val = raw.at("compose_apps");
    // if compose_apps is specified then `apps` optional configuration variable is initialized with an empty vector
    apps = boost::make_optional(std::vector<std::string>());
    if (val.length() > 0) {
      // token_compress_on allows lists like: "foo,bar", "foo, bar", or "foo bar"
      boost::split(*apps, val, boost::is_any_of(", "), boost::token_compress_on);
    }
  }

  if (raw.count("compose_apps_root") == 1) {
    apps_root = raw.at("compose_apps_root");
  }
  if (raw.count("compose_apps_tree") == 1) {
    apps_tree = raw.at("compose_apps_tree");
  }
  if (raw.count("create_apps_tree") == 1) {
    create_apps_tree = boost::lexical_cast<bool>(raw.at("create_apps_tree"));
  }
  if (raw.count("images_data_root") == 1) {
    images_data_root = raw.at("images_data_root");
  }
  if (raw.count("docker_images_reload_cmd") == 1) {
    docker_images_reload_cmd = raw.at("docker_images_reload_cmd");
  }
  if (raw.count("docker_compose_bin") == 1) {
    compose_bin = raw.at("docker_compose_bin");
  }

  if (raw.count("docker_bin") == 1) {
    docker_bin = raw.at("docker_bin");
  }

  if (raw.count("docker_prune") == 1) {
    std::string val = raw.at("docker_prune");
    boost::algorithm::to_lower(val);
    docker_prune = val != "0" && val != "false";
  }

  if (raw.count("force_update") > 0) {
    force_update = boost::lexical_cast<bool>(raw.at("force_update"));
  }
}

ComposeAppManager::ComposeAppManager(const PackageConfig& pconfig, const BootloaderConfig& bconfig,
                                     const std::shared_ptr<INvStorage>& storage,
                                     const std::shared_ptr<HttpInterface>& http,
                                     std::shared_ptr<OSTree::Sysroot> sysroot, AppEngine::Ptr app_engine)
    : OstreeManager(pconfig, bconfig, storage, http, new BootloaderLite(bconfig, *storage)),
      cfg_{pconfig},
      sysroot_{std::move(sysroot)},
      app_engine_{std::move(app_engine)} {
  if (!app_engine_) {
    app_engine_ = std::make_shared<Docker::ComposeAppEngine>(
        cfg_.apps_root, boost::filesystem::canonical(cfg_.compose_bin).string() + " ",
        std::make_shared<Docker::DockerClient>(),
        std::make_shared<Docker::RegistryClient>(pconfig.ostree_server, http));
  }

  try {
    app_tree_ = std::make_unique<ComposeAppTree>(cfg_.apps_tree.string(), cfg_.apps_root.string(),
                                                 cfg_.images_data_root.string(), cfg_.create_apps_tree);
  } catch (const std::exception& exc) {
    LOG_DEBUG << "Failed to initialize Compose App Tree (ostree) at " << cfg_.apps_tree << ". Error: " << exc.what();
  }
}

// Returns an intersection of apps specified in Target and the configuration
ComposeAppManager::AppsContainer ComposeAppManager::getApps(const Uptane::Target& t) const {
  AppsContainer apps;

  auto target_apps = t.custom_data()["docker_compose_apps"];
  for (Json::ValueIterator i = target_apps.begin(); i != target_apps.end(); ++i) {
    if ((*i).isObject() && (*i).isMember("uri")) {
      const auto& target_app_name = i.key().asString();
      const auto& target_app_uri = (*i)["uri"].asString();

      if (!!cfg_.apps) {
        // if `compose_apps` is specified in the config then add the current Target app only if it listed in
        // `compose_apps`
        for (const auto& app : *(cfg_.apps)) {
          if (target_app_name == app) {
            apps[target_app_name] = target_app_uri;
            break;
          }
        }
      } else {
        // if `compose_apps` is not specified just add all Target's apps
        apps[target_app_name] = target_app_uri;
      }

    } else {
      LOG_ERROR << "Invalid custom data for docker_compose_app: " << i.key().asString() << " -> " << *i;
    }
  }

  return apps;
}

ComposeAppManager::AppsContainer ComposeAppManager::getAppsToUpdate(const Uptane::Target& t) const {
  AppsContainer apps_to_update;

  auto currently_installed_target_apps = Target::appsJson(OstreeManager::getCurrent());
  auto new_target_apps = getApps(t);  // intersection of apps specified in Target and the configuration

  for (const auto& app_pair : new_target_apps) {
    const auto& app_name = app_pair.first;

    auto app_data = currently_installed_target_apps.get(app_name, Json::nullValue);
    if (app_data.empty()) {
      // new app in Target
      apps_to_update.insert(app_pair);
      LOG_INFO << app_name << " will be installed";
      continue;
    }

    if (app_pair.second != app_data["uri"].asString()) {
      // an existing App update
      apps_to_update.insert(app_pair);
      LOG_INFO << app_name << " will be updated";
      continue;
    }

    if (!boost::filesystem::exists(cfg_.apps_root / app_name) ||
        !boost::filesystem::exists(cfg_.apps_root / app_name / Docker::ComposeAppEngine::ComposeFile)) {
      // an App that is supposed to be installed has been removed somehow, let's install it again
      apps_to_update.insert(app_pair);
      LOG_INFO << app_name << " will be re-installed";
      continue;
    }

    LOG_DEBUG << app_name << " performing full status check";
    if (!app_engine_->isRunning({app_name, app_pair.second})) {
      // an App that is supposed to be installed and running is not fully installed or running
      apps_to_update.insert(app_pair);
      LOG_INFO << app_name << " update will be re-installed or completed";
      continue;
    }
  }

  return apps_to_update;
}

bool ComposeAppManager::checkForAppsToUpdate(const Uptane::Target& target) {
  cur_apps_to_fetch_and_update_ = getAppsToUpdate(target);
  are_apps_checked_ = true;
  return cur_apps_to_fetch_and_update_.empty();
}

bool ComposeAppManager::fetchTarget(const Uptane::Target& target, Uptane::Fetcher& fetcher, const KeyManager& keys,
                                    const FetcherProgressCb& progress_cb, const api::FlowControlToken* token) {
  if (!OstreeManager::fetchTarget(target, fetcher, keys, progress_cb, token)) {
    return false;
  }

  if (cfg_.force_update) {
    LOG_INFO << "All Apps are forced to be updated...";
    cur_apps_to_fetch_and_update_ = getApps(target);
  } else if (!are_apps_checked_) {
    // non-daemon mode (force check) or a new Target to be applied in daemon mode,
    // then do full check if Target Apps are installed and running
    LOG_INFO << "Checking for Apps to be installed or updated...";
    checkForAppsToUpdate(target);
  }

  LOG_INFO << "Found " << cur_apps_to_fetch_and_update_.size() << " Apps to update";

  bool passed = true;
  const auto& apps_uri = Target::ostreeURI(target);
  if (app_tree_ && !apps_uri.empty()) {
    LOG_INFO << "Fetching Apps Tree -> " << apps_uri;

    try {
      app_tree_->pull(config.ostree_server, keys, apps_uri);
    } catch (const std::exception& exc) {
      LOG_ERROR << "Failed to pull Apps Tree; uri: " << apps_uri << ", err: " << exc.what();
      passed = false;
    }

  } else {
    for (const auto& pair : cur_apps_to_fetch_and_update_) {
      LOG_INFO << "Fetching " << pair.first << " -> " << pair.second;
      if (!app_engine_->fetch({pair.first, pair.second})) {
        passed = false;
      }
    }
  }
  are_apps_checked_ = false;
  return passed;
}

data::InstallationResult ComposeAppManager::install(const Uptane::Target& target) const {
  data::InstallationResult res;
  Uptane::Target current = OstreeManager::getCurrent();
  if (current.sha256Hash() != target.sha256Hash()) {
    // notify the bootloader before installation happens as it is not atomic
    // and a false notification doesn't hurt with rollback support in place
    // Hacking in order to invoke non-const method from the const one !!!
    const_cast<ComposeAppManager*>(this)->updateNotify();
    res = OstreeManager::install(target);
    if (res.result_code.num_code == data::ResultCode::Numeric::kInstallFailed) {
      LOG_ERROR << "Failed to install OSTree target, skipping Docker Compose Apps";
      return res;
    }
    const_cast<ComposeAppManager*>(this)->installNotify(target);
  } else {
    LOG_INFO << "Target " << target.sha256Hash() << " is same as current";
    res = data::InstallationResult(data::ResultCode::Numeric::kOk, "OSTree hash already installed, same as current");
  }

  handleRemovedApps(target);

  const auto& apps_uri = Target::ostreeURI(target);
  if (app_tree_ && !apps_uri.empty()) {
    LOG_INFO << "Checking out updated Apps: " << apps_uri;
    try {
      const_cast<ComposeAppManager*>(this)->app_tree_->checkout(apps_uri);
    } catch (const std::exception& exc) {
      LOG_ERROR << "Failed to checkout Apps from the ostree repo; uri: " << apps_uri << ", err: " << exc.what();
      return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed,
                                      "Could not checkout Apps from the ostree repo");
    }

    LOG_INFO << "Reloading the docker image and layer store to enable the update... ";
    {
      const auto& cmd = cfg_.docker_images_reload_cmd;
      std::string out_str;
      int exit_code = Utils::shell(cmd, &out_str, true);
      LOG_TRACE << "Command: " << cmd << "\n" << out_str;

      if (exit_code != EXIT_SUCCESS) {
        LOG_ERROR << "Failed to reload the docker image and layer store, command failed: " << out_str;
        return data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Could not reload docker store");
      }
    }
    LOG_INFO << "Updated docker images has been successfully enabled";
  }
  // make sure we install what we fecthed
  if (!cur_apps_to_fetch_and_update_.empty()) {
    res.description += "\n# Apps installed:";
  }
  for (const auto& pair : cur_apps_to_fetch_and_update_) {
    LOG_INFO << "Installing " << pair.first << " -> " << pair.second;
    const bool just_install = res.result_code == data::ResultCode::Numeric::kNeedCompletion;
    // I have no idea via the package manager interface method install() is const which is not a const
    // method by its definition/nature
    auto& non_const_app_engine = (const_cast<ComposeAppManager*>(this))->app_engine_;
    auto run_res = just_install ? non_const_app_engine->install({pair.first, pair.second})
                                : non_const_app_engine->run({pair.first, pair.second});
    if (!run_res) {
      res = data::InstallationResult(data::ResultCode::Numeric::kInstallFailed, "Could not install app");
    } else {
      res.description += "\n" + pair.second;
    }
  };

  // there is no much reason in re-trying to install app if its installation has failed for the first time
  // TODO: we might add more advanced logic here, e.g. try to install a few times and then fail
  cur_apps_to_fetch_and_update_.clear();

  if (cfg_.docker_prune) {
    LOG_INFO << "Pruning unused docker images";
    // Utils::shell which isn't interactive, we'll use std::system so that
    // stdout/stderr is streamed while docker sets things up.
    if (std::system("docker image prune -a -f --filter=\"label!=aktualizr-no-prune\"") != 0) {
      LOG_WARNING << "Unable to prune unused docker images";
    }
  }

  return res;
}

data::InstallationResult ComposeAppManager::finalizeInstall(const Uptane::Target& target) {
  auto ir = OstreeManager::finalizeInstall(target);

  const auto& current_apps = getApps(target);
  for (const auto& app_pair : current_apps) {
    const auto& app_name = app_pair.first;
    auto need_start_flag = cfg_.apps_root / app_name / Docker::ComposeAppEngine::NeedStartFile;
    if (boost::filesystem::exists(need_start_flag)) {
      if (ir.result_code.num_code == data::ResultCode::Numeric::kOk) {
        app_engine_->run({app_pair.first, app_pair.second});
      }
      boost::filesystem::remove(need_start_flag);
    }
  }

  if (data::ResultCode::Numeric::kNeedCompletion != ir.result_code.num_code) {
    ir.description += "\n# Apps running:\n" + containerDetails();
  }
  return ir;
}

// Handle the case like:
//  1) sota.toml is configured with 2 compose apps: "app1, app2"
//  2) update is applied, so we are now running both app1 and app2
//  3) sota.toml is updated with 1 docker app: "app1"
// At this point we should stop app2 and remove it.
void ComposeAppManager::handleRemovedApps(const Uptane::Target& target) const {
  if (!boost::filesystem::is_directory(cfg_.apps_root)) {
    LOG_DEBUG << "cfg_.apps_root does not exist";
    return;
  }

  // an intersection of apps specified in Target and the configuration
  // i.e. the apps that are supposed to be installed and running
  const auto& current_apps = getApps(target);

  for (auto& entry : boost::make_iterator_range(boost::filesystem::directory_iterator(cfg_.apps_root), {})) {
    if (boost::filesystem::is_directory(entry)) {
      std::string name = entry.path().filename().native();
      if (current_apps.find(name) == current_apps.end()) {
        LOG_WARNING << "Docker Compose App(" << name
                    << ") installed, "
                       "but is either removed from configuration or not defined in current Target. "
                       "Removing from system";

        // I have no idea via the package manager interface method install() is const which is not a const
        // method by its definition/nature
        auto& non_const_app_engine = (const_cast<ComposeAppManager*>(this))->app_engine_;
        non_const_app_engine->remove({name, ""});
      }
    }
  }
}

std::string ComposeAppManager::getCurrentHash() const { return sysroot_->getCurDeploymentHash(); }

std::string ComposeAppManager::containerDetails() const {
  std::string cmd = cfg_.docker_bin.string();
  cmd +=
      " ps --format 'App({{.Label \"com.docker.compose.project\"}}) Service({{.Label "
      "\"com.docker.compose.service\"}} {{.Label \"io.compose-spec.config-hash\"}})'";
  std::string out_str;
  int exit_code = Utils::shell(cmd, &out_str, true);
  LOG_TRACE << "Command: " << cmd << "\n" << out_str;
  if (exit_code != EXIT_SUCCESS) {
    out_str = "Unable to run `docker ps`";
  }
  return out_str;
}
