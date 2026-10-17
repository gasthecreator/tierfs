#include "service.hpp"

#include <algorithm>
#include <set>

namespace tierfs {

namespace {

bool valid_name(const std::string& n) {
    if (n.empty() || n.size() > 40 || n[0] == '.') return false;
    for (char c : n)
        if (!(isalnum(static_cast<unsigned char>(c)) || c == '.' || c == '_' || c == '-')) return false;
    return true;
}

// Well-formed UTF-8 as XML needs it: shortest forms only, no surrogates, nothing above U+10FFFF, none of the non-characters U+FFFE and U+FFFF.
// (A path with bytes that are not UTF-8 would make a plist that the system's own parser refuses, found by fuzzing.)
bool valid_utf8(const std::string& s) {
    size_t i = 0;
    while (i < s.size()) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        size_t n = c < 0x80 ? 1 : (c >= 0xC2 && c <= 0xDF) ? 2 : (c >= 0xE0 && c <= 0xEF) ? 3 : (c >= 0xF0 && c <= 0xF4) ? 4 : 0;
        if (n == 0 || i + n > s.size()) return false;
        uint32_t cp = n == 1 ? c : n == 2 ? (c & 0x1F) : n == 3 ? (c & 0x0F) : (c & 0x07);
        for (size_t k = 1; k < n; k++) {
            unsigned char t = static_cast<unsigned char>(s[i + k]);
            if ((t & 0xC0) != 0x80) return false;
            cp = (cp << 6) | (t & 0x3F);
        }
        if ((n == 3 && cp < 0x800) || (n == 4 && cp < 0x10000) || cp > 0x10FFFF) return false;  // not the shortest form, or too large
        if (cp >= 0xD800 && cp <= 0xDFFF) return false;                                         // a surrogate
        if (cp == 0xFFFE || cp == 0xFFFF) return false;
        i += n;
    }
    return true;
}

bool clean_text(const std::string& s) {
    for (char c : s)
        if (static_cast<unsigned char>(c) < 0x20 || c == 0x7f) return false;
    return valid_utf8(s);
}

const std::set<std::string>& known_options() {
    static const std::set<std::string> k = {"origin",    "prefix",      "ledger",     "keyfile",         "devices",      "control",
                                            "maint",     "waitms",      "background", "notify",          "scan",         "cachemb",
                                            "readahead", "gc",          "gckeep",     "gcretentiondays", "lowgb",        "criticalgb",
                                            "lowpct",    "criticalpct", "spacecheck", "useino",  "namedattr",       "noappledouble"};
    return k;
}

bool is_flag(const std::string& k) { return k == "namedattr" || k == "noappledouble"; }

}  // namespace

std::string service_label(const std::string& name) { return "local.tierfs." + name; }

std::string lexical_path(const std::string& p) {
    std::vector<std::string> parts;
    size_t i = 0;
    while (i <= p.size()) {
        size_t j = p.find('/', i);
        if (j == std::string::npos) j = p.size();
        std::string c = p.substr(i, j - i);
        if (c == "..") {
            if (!parts.empty()) parts.pop_back();
        } else if (!c.empty() && c != ".") {
            parts.push_back(c);
        }
        i = j + 1;
    }
    std::string out;
    for (auto& c : parts) out += "/" + c;
    return out.empty() ? "/" : out;
}

bool path_is_inside(const std::string& inner, const std::string& outer) {
    std::string a = lexical_path(inner), b = lexical_path(outer);
    if (a == b) return true;
    if (b == "/") return true;
    return a.size() > b.size() && a.compare(0, b.size(), b) == 0 && a[b.size()] == '/';
}

std::string join_options(const std::vector<std::pair<std::string, std::string>>& options) {
    std::string out;
    for (auto& kv : options) {
        if (!out.empty()) out += ",";
        out += kv.first;
        if (!kv.second.empty() || !is_flag(kv.first)) out += "=" + kv.second;
    }
    return out;
}

std::string validate_service(const ServiceSpec& s) {
    if (!valid_name(s.name)) return "the name must be 1-40 characters of letters, digits, '.', '_' or '-', and not start with a dot";
    if (s.binary.empty() || s.binary[0] != '/' || !clean_text(s.binary)) return "the tierfsd path must be absolute";
    if (s.mountpoint.empty() || s.mountpoint[0] != '/' || !clean_text(s.mountpoint)) return "the mountpoint must be an absolute path";
    if (s.log_dir.empty() || s.log_dir[0] != '/' || !clean_text(s.log_dir)) return "the log directory must be an absolute path";
    std::set<std::string> seen;
    std::string origin, ledger, keyfile, prefix;
    for (auto& kv : s.options) {
        const std::string &k = kv.first, &v = kv.second;
        if (!known_options().count(k)) return "unknown option '" + k + "'";
        if (!seen.insert(k).second) return "option '" + k + "' is given twice";
        if (is_flag(k) && !v.empty()) return "option '" + k + "' takes no value";
        if (!is_flag(k) && v.empty()) return "option '" + k + "' needs a value";
        if (v.find(',') != std::string::npos) return "the value of '" + k + "' contains a comma (it would start another option)";
        if (!clean_text(v)) return "the value of '" + k + "' contains a control character";
        if (k == "origin") origin = v;
        if (k == "ledger") ledger = v;
        if (k == "keyfile") keyfile = v;
        if (k == "prefix") prefix = v;
        if ((k == "maint" || k == "waitms" || k == "cachemb" || k == "readahead" || k == "gckeep" || k == "gcretentiondays" || k == "lowgb" ||
             k == "criticalgb" || k == "lowpct" || k == "criticalpct" || k == "spacecheck") &&
            (v.empty() || v.find_first_not_of("0123456789-") != std::string::npos || v == "-"))
            return "the value of '" + k + "' must be a number";
        if ((k == "background" || k == "notify" || k == "scan" || k == "gc" || k == "useino") && v != "0" && v != "1")
            return "the value of '" + k + "' must be 0 or 1";
    }
    for (const char* need : {"origin", "prefix", "ledger", "keyfile"})
        if (!seen.count(need)) return std::string("the option '") + need + "' is required";
    if (origin[0] != '/') return "origin must be an absolute path";
    if (ledger[0] != '/') return "ledger must be an absolute path";
    if (prefix[0] != '/') return "prefix must start with '/'";
    // The key never lives in the plist: the Keychain, a key store directory, or a key file's path.
    if (keyfile != "keychain" && !(keyfile.compare(0, 4, "dir:") == 0 && keyfile.size() > 4 && keyfile[4] == '/') && keyfile[0] != '/')
        return "keyfile must be 'keychain', 'dir:/absolute/path' or the absolute path of a key file";
    if (path_is_inside(s.mountpoint, origin)) return "the mountpoint is the origin folder or inside it (the filesystem would read itself)";
    if (path_is_inside(origin, s.mountpoint)) return "the origin folder is inside the mountpoint (mounting would hide it)";
    if (path_is_inside(ledger, s.mountpoint)) return "the ledger is inside the mountpoint (mounting would hide it)";
    return "";
}

std::string xml_escape(const std::string& s) {
    std::string out;
    for (char c : s) {
        switch (c) {
            case '&':
                out += "&amp;";
                break;
            case '<':
                out += "&lt;";
                break;
            case '>':
                out += "&gt;";
                break;
            case '"':
                out += "&quot;";
                break;
            case '\'':
                out += "&apos;";
                break;
            default:
                out += c;
        }
    }
    return out;
}

std::string render_service_plist(const ServiceSpec& s) {
    std::string log = s.log_dir;
    while (!log.empty() && log.back() == '/') log.pop_back();
    log += "/" + s.name + ".log";
    std::string x =
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n"
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n"
        "<plist version=\"1.0\">\n<dict>\n";
    auto key = [&](const std::string& k) { x += "  <key>" + k + "</key>\n"; };
    auto str = [&](const std::string& k, const std::string& v) {
        key(k);
        x += "  <string>" + xml_escape(v) + "</string>\n";
    };
    auto boolean = [&](const std::string& k, bool v) {
        key(k);
        x += v ? "  <true/>\n" : "  <false/>\n";
    };
    str("Label", service_label(s.name));
    key("ProgramArguments");
    x += "  <array>\n";
    for (const std::string& a : {s.binary, std::string("-o"), join_options(s.options), s.mountpoint})
        x += "    <string>" + xml_escape(a) + "</string>\n";
    x += "  </array>\n";
    boolean("RunAtLoad", s.run_at_load);
    boolean("KeepAlive", false);  // a crashed mount is looked at by a person, not restarted in a loop
    str("WorkingDirectory", "/");
    str("StandardOutPath", log);
    str("StandardErrorPath", log);
    str("ProcessType", "Background");
    x += "</dict>\n</plist>\n";
    return x;
}

}  // namespace tierfs
