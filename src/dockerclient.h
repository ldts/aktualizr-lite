#ifndef AKTUALIZR_LITE_DOCKERCLIENT_H
#define AKTUALIZR_LITE_DOCKERCLIENT_H

#include <json/json.h>
#include <string>

namespace Docker {

class DockerClientIF {
 public:
  DockerClientIF() { }
  bool serviceRunning(std::string& service, std::string& hash) { return true; }
};

class DockerClient : public DockerClientIF {
 public:
  DockerClient(const std::string& app, bool curl = false);
  bool serviceRunning(std::string& service, std::string& hash);

 private:
  Json::Value root_;
};

}  // namespace Docker

#endif  // AKTUALIZR_LITE_DOCKERCLIENT_H
