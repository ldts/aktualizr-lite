#include <gtest/gtest.h>
#include "composeinfo.h"
#include "logging/logging.h"
#include "yaml2json.h"

class Yaml2JsonTest : public ::testing::Test {
 protected:
  Yaml2JsonTest() {}
};

TEST_F(Yaml2JsonTest, check_template) {
  try {
    Yaml2Json json("tests/template.yaml");
    ASSERT_EQ(json.root_["version"], "3.2");
    ASSERT_EQ(json.root_["services"]["dns64"]["image"], "hub.foundries.io/lmp/dns64:latest");
    ASSERT_EQ(json.root_["services"]["dns64"]["tmpfs"][1], "/var/lock");
  } catch (...) {
    ASSERT_TRUE(false);
  }
}

TEST_F(Yaml2JsonTest, compose_parser) {
  try {
    Docker::ComposeInfo parser("tests/template.yaml");

    // obtain all the services in the template file (we know there are 5)
    std::vector<Json::Value> services;
    if (!parser.getServices(services)) ASSERT_TRUE(false);

    // check all services's images are what we expect
    for (std::vector<Json::Value>::iterator it = services.begin(); it != services.end(); ++it) {
      std::string image;
      if (!parser.getServiceImage(*it, image)) continue;

      Json::Value val = *it;
      if (val.asString() == "iface-mon-ot")
        ASSERT_EQ(image, "hub.foundries.io/lmp/iface-monitor:latest");
      else if (val.asString() == "ot-wpantund")
        ASSERT_EQ(image, "hub.foundries.io/lmp/ot-wpantund:latest");
      else if (val.asString() == "dns64")
        ASSERT_EQ(image, "hub.foundries.io/lmp/dns64:latest");
      else if (val.asString() == "jool")
        ASSERT_EQ(image, "hub.foundries.io/lmp/nat64-jool:latest");
      else if (val.asString() == "californium-proxy")
        ASSERT_EQ(image, "hub.foundries.io/lmp/cf-proxy-coap-http:latest");
      else
        ASSERT_TRUE(false);
    }
    ASSERT_EQ(parser.getNbrImages(), 5);
  } catch (...) {
    ASSERT_TRUE(false);
  }
}

int main(int argc, char **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
