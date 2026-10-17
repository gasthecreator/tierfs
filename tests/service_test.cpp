// Tests of the LaunchAgent plist and its safety checks (core/service.*). The plist is read back by macOS's own plutil, so the XML is judged by
// a parser that is not ours.
#include <unistd.h>

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <functional>

#include "../core/service.hpp"

using namespace tierfs;

static int failures = 0;
static bool failfast() {
    static const bool f = getenv("TIERFS_TEST_FAILFAST") != nullptr;
    return f;
}
#define CHECK(cond)                                         \
    do {                                                    \
        if (!(cond)) {                                      \
            printf("FAIL  line %d: %s\n", __LINE__, #cond); \
            failures++;                                     \
            if (failfast()) {                               \
                fflush(stdout);                             \
                _exit(1);                                   \
            }                                               \
        } else                                              \
            printf("PASS  %s\n", #cond);                    \
    } while (0)

static bool has(const std::string& s, const std::string& n) { return s.find(n) != std::string::npos; }

static std::string sh(const std::string& cmd, int* rc = nullptr) {
    FILE* f = popen((cmd + " 2>&1").c_str(), "r");
    std::string out;
    char buf[1024];
    while (f && fgets(buf, sizeof buf, f)) out += buf;
    int st = f ? pclose(f) : -1;
    if (rc) *rc = st;
    return out;
}

static ServiceSpec good() {
    ServiceSpec s;
    s.name = "projects";
    s.binary = "/opt/tierfs/bin/tierfsd";
    s.mountpoint = "/Users/me/Projects";
    s.log_dir = "/Users/me/Library/Logs/tierfs";
    s.options = {{"origin", "/Users/me/.tierfs/Projects-real"},
                 {"prefix", "/Users/me/Projects/"},
                 {"ledger", "/Users/me/.tierfs/ledger"},
                 {"keyfile", "keychain"},
                 {"devices", "nas.local:9100@0123456789abcdef+127.0.0.1:9101"},
                 {"namedattr", ""}};
    return s;
}

// What plutil makes of the rendered plist: empty on a syntax error.
struct Plist {
    std::string path;
    bool valid = false;
    explicit Plist(const std::string& xml) {
        char t[] = "/tmp/tierfs-svctest-XXXXXX";
        int fd = mkstemp(t);
        path = t;
        close(fd);
        std::ofstream(path) << xml;
        int rc = 1;
        sh("plutil -lint '" + path + "'", &rc);
        valid = rc == 0;
    }
    ~Plist() { unlink(path.c_str()); }
    std::string get(const std::string& keypath) {
        int rc = 1;
        std::string out = sh("plutil -extract '" + keypath + "' raw -o - '" + path + "'", &rc);
        if (rc != 0) return "<missing>";
        if (!out.empty() && out.back() == '\n') out.pop_back();  // (plutil ends its answer with a newline)
        return out;
    }
};

int main() {
    printf("== paths are compared as text, with . and .. resolved\n");
    CHECK(lexical_path("/a/b/c") == "/a/b/c" && lexical_path("/a//b/") == "/a/b" && lexical_path("/a/./b") == "/a/b" &&
          lexical_path("/a/b/../c") == "/a/c");
    CHECK(lexical_path("/") == "/" && lexical_path("") == "/" && lexical_path("/..") == "/" && lexical_path("/a/../..") == "/" &&
          lexical_path("/a/b/..") == "/a");
    CHECK(path_is_inside("/a/b", "/a") && path_is_inside("/a", "/a") && path_is_inside("/a/", "/a") && path_is_inside("/a/b/c", "/a/b"));
    CHECK(!path_is_inside("/a", "/a/b") && !path_is_inside("/ab", "/a") && !path_is_inside("/a/bc", "/a/b") && !path_is_inside("/x/y", "/a"));
    CHECK(path_is_inside("/anything/at/all", "/") && path_is_inside("/a/b/../c", "/a/c") && !path_is_inside("/a/b/../c", "/a/b"));

    printf("== a sound spec is accepted\n");
    CHECK(validate_service(good()).empty());
    {
        ServiceSpec s = good();
        s.options.push_back({"gc", "1"});
        s.options.push_back({"readahead", "-1"});
        s.options.push_back({"cachemb", "128"});
        s.options.push_back({"background", "0"});
        s.options.push_back({"keyfile2", ""});
        CHECK(!validate_service(s).empty());  // (an unknown option)
        s.options.pop_back();
        CHECK(validate_service(s).empty());
        s.options[3].second = "dir:/Users/me/.tierfs/keys";
        CHECK(validate_service(s).empty());
        s.options[3].second = "/Users/me/.tierfs/key";
        CHECK(validate_service(s).empty());
    }

    {  // spaces are fine in paths; the other flag and the control socket are known options
        ServiceSpec s = good();
        s.mountpoint = "/Users/me/My Projects";
        s.log_dir = "/Users/me/My Logs";
        s.options.push_back({"noappledouble", ""});
        s.options.push_back({"control", "/Users/me/My Projects.sock"});
        CHECK(validate_service(s).empty());
        Plist p(render_service_plist(s));
        CHECK(p.valid && p.get("ProgramArguments.3") == "/Users/me/My Projects" && p.get("StandardOutPath") == "/Users/me/My Logs/projects.log");
        CHECK(has(p.get("ProgramArguments.2"), "namedattr,noappledouble,control=/Users/me/My Projects.sock") ||
              has(p.get("ProgramArguments.2"), ",namedattr,noappledouble,control=/Users/me/My Projects.sock"));
    }

    printf("== what is refused, and why\n");
    auto bad = [&](const std::function<void(ServiceSpec&)>& f) {
        ServiceSpec s = good();
        f(s);
        return validate_service(s);
    };
    auto opt = [&](ServiceSpec& s, const std::string& k, const std::string& v) {
        for (auto& kv : s.options)
            if (kv.first == k) kv.second = v;
    };
    CHECK(has(bad([](ServiceSpec& s) { s.name = ""; }), "name must be") && has(bad([](ServiceSpec& s) { s.name = ".hidden"; }), "name must be") &&
          has(bad([](ServiceSpec& s) { s.name = "a b"; }), "name must be") && has(bad([](ServiceSpec& s) { s.name = "a/b"; }), "name must be") &&
          has(bad([](ServiceSpec& s) { s.name = std::string(41, 'a'); }), "name must be") &&
          bad([](ServiceSpec& s) { s.name = std::string(40, 'a'); }).empty() && bad([](ServiceSpec& s) { s.name = "A.b_c-9"; }).empty());
    CHECK(has(bad([](ServiceSpec& s) { s.binary = "tierfsd"; }), "tierfsd path") && has(bad([](ServiceSpec& s) { s.binary = ""; }), "tierfsd path") &&
          has(bad([](ServiceSpec& s) { s.binary = "/x\n/y"; }), "tierfsd path"));
    CHECK(has(bad([](ServiceSpec& s) { s.mountpoint = "Projects"; }), "mountpoint must be") &&
          has(bad([](ServiceSpec& s) { s.mountpoint = ""; }), "mountpoint must be") &&
          has(bad([](ServiceSpec& s) { s.mountpoint = "/Users/me/P\nQ"; }), "mountpoint must be"));
    CHECK(has(bad([](ServiceSpec& s) { s.log_dir = "logs"; }), "log directory") &&
          has(bad([](ServiceSpec& s) { s.log_dir = ""; }), "log directory") &&
          has(bad([](ServiceSpec& s) { s.log_dir = "/Users/me/L\tL"; }), "log directory"));
    CHECK(has(bad([](ServiceSpec& s) { s.options.push_back({"frobnicate", "1"}); }), "unknown option 'frobnicate'"));
    CHECK(has(bad([](ServiceSpec& s) { s.options.push_back({"origin", "/other"}); }), "'origin' is given twice"));
    CHECK(has(bad([&](ServiceSpec& s) { opt(s, "namedattr", "yes"); }), "takes no value") &&
          has(bad([&](ServiceSpec& s) { opt(s, "origin", ""); }), "needs a value"));
    CHECK(has(bad([&](ServiceSpec& s) { opt(s, "devices", "a:1,b:2"); }), "comma") &&
          has(bad([&](ServiceSpec& s) { opt(s, "devices", "a:1\nb"); }), "control character") &&
          has(bad([&](ServiceSpec& s) { opt(s, "devices", std::string("a\x7f")); }), "control character"));
    for (const char* need : {"origin", "prefix", "ledger", "keyfile"})
        CHECK(has(bad([&](ServiceSpec& s) {
                      s.options.erase(std::remove_if(s.options.begin(), s.options.end(), [&](auto& kv) { return kv.first == need; }),
                                      s.options.end());
                  }),
                  std::string("'") + need + "' is required"));
    CHECK(has(bad([&](ServiceSpec& s) { opt(s, "origin", "relative/dir"); }), "origin must be an absolute") &&
          has(bad([&](ServiceSpec& s) { opt(s, "ledger", "ledger"); }), "ledger must be an absolute") &&
          has(bad([&](ServiceSpec& s) { opt(s, "prefix", "Projects/"); }), "prefix must start"));
    CHECK(
        has(bad([&](ServiceSpec& s) { opt(s, "keyfile", "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"); }), "keyfile must be") &&
        has(bad([&](ServiceSpec& s) { opt(s, "keyfile", "dir:relative"); }), "keyfile must be") &&
        has(bad([&](ServiceSpec& s) { opt(s, "keyfile", "dir:"); }), "keyfile must be") &&
        has(bad([&](ServiceSpec& s) { opt(s, "keyfile", "Keychain"); }), "keyfile must be"));
    for (const char* k :
         {"maint", "waitms", "cachemb", "readahead", "gckeep", "gcretentiondays", "lowgb", "criticalgb", "lowpct", "criticalpct", "spacecheck"}) {
        CHECK(has(bad([&](ServiceSpec& s) { s.options.push_back({k, "abc"}); }), "must be a number") &&
              has(bad([&](ServiceSpec& s) { s.options.push_back({k, "-"}); }), "must be a number") &&
              has(bad([&](ServiceSpec& s) { s.options.push_back({k, "1x"}); }), "must be a number") &&
              bad([&](ServiceSpec& s) { s.options.push_back({k, "12"}); }).empty());
    }
    for (const char* k : {"background", "notify", "scan", "gc", "useino"})
        CHECK(has(bad([&](ServiceSpec& s) { s.options.push_back({k, "2"}); }), "must be 0 or 1") &&
              bad([&](ServiceSpec& s) { s.options.push_back({k, "0"}); }).empty() &&
              bad([&](ServiceSpec& s) { s.options.push_back({k, "1"}); }).empty());
    // text the plist cannot hold: bytes that are not UTF-8 (the system's own parser refuses such a plist), overlong forms, surrogates, non-characters
    for (const char* bad_text :
         {"/Users/m\xff"
          "e",
          "/Users/m\xc3", "/Users/m\xc0\xaf", "/Users/m\xed\xa0\x80", "/Users/m\xef\xbf\xbf", "/Users/m\xf4\x90\x80\x80", "/Users/m\xe0\x80\x80",
          "/Users/m\x80", "/Users/m\xc3(", "/Users/m\xe2\x82(", "/Users/m\xf0\x9f\x98(", "/Users/m\xf0\x80\x80\x80", "/Users/m\xf0\x8f\xbf\xbf",
          "/Users/m\xed\xbf\xbf", "/Users/m\xef\xbf\xbe", "/Users/m\xf5\x80\x80\x80"}) {
        CHECK(!bad([&](ServiceSpec& s) { s.mountpoint = bad_text; }).empty());
        CHECK(!bad([&](ServiceSpec& s) { opt(s, "origin", bad_text); }).empty());
    }
    for (const char* good_text : {"/Users/m\xc3\xa9", "/Users/\xe6\x97\xa5\xe6\x9c\xac", "/Users/m\xf0\x9f\x98\x80", "/Users/m\xc2\xa0"})
        CHECK(bad([&](ServiceSpec& s) { s.log_dir = good_text; }).empty());  // real names with accents, other scripts and emoji stay allowed
    // the mountpoint and the origin must not be the same place, nested, or confusable
    CHECK(has(bad([](ServiceSpec& s) { s.mountpoint = "/Users/me/.tierfs/Projects-real"; }), "inside it"));
    CHECK(has(bad([](ServiceSpec& s) { s.mountpoint = "/Users/me/.tierfs/Projects-real/sub"; }), "inside it"));
    CHECK(has(bad([](ServiceSpec& s) { s.mountpoint = "/Users/me/.tierfs/Projects-real/../Projects-real/"; }), "inside it"));
    CHECK(has(bad([&](ServiceSpec& s) {
                  s.mountpoint = "/Users/me";
                  opt(s, "ledger", "/var/ledger");
              }),
              "origin folder is inside the mountpoint"));
    CHECK(has(bad([&](ServiceSpec& s) {
                  s.mountpoint = "/";
                  opt(s, "ledger", "/var/ledger");
              }),
              "origin folder is inside the mountpoint"));
    CHECK(has(bad([](ServiceSpec& s) { s.mountpoint = "/Users/me"; }), "inside the mountpoint"));
    CHECK(bad([](ServiceSpec& s) { s.mountpoint = "/Users/me/.tierfs/Projects-real2"; }).empty());  // a sibling with the same beginning is fine
    CHECK(has(bad([&](ServiceSpec& s) { opt(s, "ledger", "/Users/me/Projects/ledger"); }), "ledger is inside the mountpoint"));
    CHECK(bad([&](ServiceSpec& s) { opt(s, "ledger", "/Users/me/Projects2/ledger"); }).empty());

    printf("== the options as tierfsd receives them\n");
    CHECK(join_options({}).empty() && join_options({{"a", "1"}}) == "a=1" && join_options({{"a", "1"}, {"b", "2"}}) == "a=1,b=2");
    CHECK(join_options({{"namedattr", ""}, {"origin", "/x"}}) == "namedattr,origin=/x" && join_options({{"readahead", "-1"}}) == "readahead=-1");
    CHECK(join_options({{"a", ""}}) == "a=");  // (only the two known flags go without a value)

    printf("== the plist, read back by plutil\n");
    {
        Plist p(render_service_plist(good()));
        CHECK(p.valid);
        CHECK(p.get("Label") == "local.tierfs.projects");
        CHECK(p.get("ProgramArguments.0") == "/opt/tierfs/bin/tierfsd" && p.get("ProgramArguments.1") == "-o" &&
              p.get("ProgramArguments.3") == "/Users/me/Projects" && p.get("ProgramArguments.4") == "<missing>");
        CHECK(p.get("ProgramArguments.2") ==
              "origin=/Users/me/.tierfs/Projects-real,prefix=/Users/me/Projects/,ledger=/Users/me/.tierfs/ledger,keyfile=keychain,"
              "devices=nas.local:9100@0123456789abcdef+127.0.0.1:9101,namedattr");
        CHECK(p.get("RunAtLoad") == "false" && p.get("KeepAlive") == "false" && p.get("WorkingDirectory") == "/" &&
              p.get("ProcessType") == "Background");
        CHECK(p.get("StandardOutPath") == "/Users/me/Library/Logs/tierfs/projects.log" &&
              p.get("StandardErrorPath") == "/Users/me/Library/Logs/tierfs/projects.log");
    }
    {
        ServiceSpec s = good();
        s.run_at_load = true;
        s.log_dir = "/Users/me/logs///";
        Plist p(render_service_plist(s));
        CHECK(p.valid && p.get("RunAtLoad") == "true" && p.get("StandardOutPath") == "/Users/me/logs/projects.log");
        s.log_dir = "/";
        Plist root(render_service_plist(s));
        CHECK(root.get("StandardOutPath") == "/projects.log");
        s.log_dir = "/Users/me/L&L";
        Plist amp(render_service_plist(s));
        CHECK(amp.valid && amp.get("StandardOutPath") == "/Users/me/L&L/projects.log" &&
              amp.get("StandardErrorPath") == "/Users/me/L&L/projects.log");
    }
    {  // text that XML treats specially survives the round trip
        ServiceSpec s = good();
        s.binary = "/opt/t&t/<tierfsd>'\"";
        s.mountpoint = "/Users/me/M&M";
        Plist p(render_service_plist(s));
        CHECK(p.valid && p.get("ProgramArguments.0") == "/opt/t&t/<tierfsd>'\"" && p.get("ProgramArguments.3") == "/Users/me/M&M");
        CHECK(xml_escape("a&b<c>d\"e'f") == "a&amp;b&lt;c&gt;d&quot;e&apos;f" && xml_escape("plain") == "plain" && xml_escape("").empty());
    }
    printf("\n%s (%d failures)\n", failures ? "FAILED" : "ALL PASSED", failures);
    return failures ? 1 : 0;
}
