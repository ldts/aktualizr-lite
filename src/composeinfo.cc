#include "composeinfo.h"
#include <glib.h>
#include "logging/logging.h"
#include "yaml2json.h"

namespace Docker {

ComposeInfo::ComposeInfo(const std::string& file) : json_(file) {}

bool ComposeInfo::getServices(std::vector<Json::Value>& services) {
  Json::Value p = json_.root_["services"];

  for (Json::ValueIterator ii = p.begin(); ii != p.end(); ++ii) services.push_back(ii.key());

  return !services.empty();
}

bool ComposeInfo::getServiceImage(const Json::Value& service, std::string& image) {
  image = json_.root_["services"][service.asString()]["image"].asString();
  if (image == std::string()) return false;
  return true;
}

bool ComposeInfo::getServiceHash(const Json::Value& service, std::string& hash) {
  hash = json_.root_["services"][service.asString()]["labels"]["io.compose-spec.config-hash"].asString();
  if (hash == std::string()) return false;
  return true;
}

int ComposeInfo::getNbrImages(void) {
  Json::Value p = json_.root_["services"];
  int nbr_images = 0;
  std::string image;

  for (Json::ValueIterator ii = p.begin(); ii != p.end(); ++ii) {
    image = json_.root_["services"][ii.key().asString()]["image"].asString();
    if (image != std::string()) nbr_images++;
  }
  return nbr_images;
}

}  // namespace Docker
