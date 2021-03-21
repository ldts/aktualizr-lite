#ifndef AKTUALIZR_LITE_COMPOSEINFO_H
#define AKTUALIZR_LITE_COMPOSEINFO_H

#include <json/json.h>
#include <string>
#include <vector>
#include "yaml2json.h"
namespace Docker {

class ComposeInfo {
 public:
  ComposeInfo(const std::string& yaml);
  bool getServices(std::vector<Json::Value>& services);
  bool getServiceImage(const Json::Value& service, std::string& image);
  bool getServiceHash(const Json::Value& service, std::string& hash);
  int getNbrImages(void);

 private:
  Yaml2Json json_;
};

}  // namespace Docker

#endif  // AKTUALIZR_LITE_COMPOSEINFO_H
