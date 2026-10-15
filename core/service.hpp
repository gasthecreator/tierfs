// Running tierfsd as a macOS LaunchAgent: the plist for it, and the checks that keep a mistake in it from becoming a dangerous mount.
// Pure functions (no launchctl here): `tierctl service` uses them and does the file and launchctl work.
//
// What the checks are for: tierfsd mounts a filesystem OVER a folder, and a wrong path there is the kind of mistake that hides the real files or
// loops the filesystem into itself. So the mountpoint may not be, contain or lie inside the origin folder; every path must be absolute; the key
// must come from the Keychain or a key store, never be typed into the plist; and option values cannot smuggle in extra -o options (a comma) or
// extra lines. The agent does NOT restart a crashed mount by itself (KeepAlive off) and does not start at login unless asked.
#pragma once

#include <string>
#include <utility>
#include <vector>

namespace tierfs {

struct ServiceSpec {
    std::string name;                                      // [A-Za-z0-9._-], not starting with a dot; the label is local.tierfs.<name>
    std::string binary;                                    // absolute path of tierfsd
    std::string mountpoint;                                // absolute
    std::vector<std::pair<std::string, std::string>> options;   // -o key=value (an empty value is a flag such as namedattr)
    std::string log_dir;                                   // absolute; the log is <log_dir>/<name>.log
    bool run_at_load = false;
};

std::string service_label(const std::string& name);
// The first problem with the spec, or empty if it is sound.
std::string validate_service(const ServiceSpec& s);
// The plist (XML). Call validate_service first: this renders whatever it is given.
std::string render_service_plist(const ServiceSpec& s);
std::string xml_escape(const std::string& s);
// The -o argument as tierfsd receives it: "origin=/a,prefix=/b/,namedattr".
std::string join_options(const std::vector<std::pair<std::string, std::string>>& options);
// A path with "." and ".." and repeated or trailing slashes resolved by text alone (no filesystem access, no symlinks).
std::string lexical_path(const std::string& p);
bool path_is_inside(const std::string& inner, const std::string& outer);   // equal counts as inside

}  // namespace tierfs
