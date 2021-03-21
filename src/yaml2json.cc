#include "yaml2json.h"
#include <glib.h>
#include <logging/logging.h>

Yaml2Json::Yaml2Json(const std::string& file) {
  g_autofree gchar* stdout_buff = nullptr;
  g_autofree gchar* stderr_buff = nullptr;
  g_autofree GError* error = nullptr;
  gint status;

  LOG_DEBUG << "Opening: " << file;
  if (g_spawn_command_line_sync(("fy-tool --mode json " + file).c_str(), &stdout_buff, &stderr_buff, &status, &error)) {
    if (!status && !error) {
      std::istringstream sin(stdout_buff);
      sin >> root_;
      return;
    }
  }
  throw std::runtime_error(("fy-tool --mode json " + file).c_str());
}
