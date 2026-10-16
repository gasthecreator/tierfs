// Tests of device discovery (core/discovery.*): the advertisement format and the rules for choosing a device are checked exactly, with no network;
// then a real advertisement is published through the system's mDNS service and found again.
#include <unistd.h>

#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <thread>

#include "../core/discovery.hpp"

using namespace tierfs::discovery;

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

static const char* KID = "0123456789abcdef";
static const char* KID2 = "fedcba9876543210";

static std::vector<uint8_t> raw(std::initializer_list<const char*> items) {
    std::vector<uint8_t> v;
    for (const char* s : items) {
        v.push_back(static_cast<uint8_t>(strlen(s)));
        v.insert(v.end(), s, s + strlen(s));
    }
    return v;
}
static bool parses(const std::vector<uint8_t>& v, Advert* a = nullptr) { return parse_txt(v.data(), v.size(), a); }

static Found dev(const char* name, const char* host, uint16_t port, const char* kid, bool paired) {
    Found f;
    f.name = name;
    f.host = host;
    f.port = port;
    f.key_id = kid;
    f.paired = paired;
    return f;
}

int main() {
    // ---- the TXT record
    {
        Advert a;
        a.key_id = KID;
        a.paired = true;
        auto t = encode_txt(a);
        Advert back;
        CHECK(parses(t, &back) && back.key_id == KID && back.paired);
        CHECK(t == raw({"v=1", "auth=1", "kid=0123456789abcdef"}));
        Advert open_dev;
        auto t2 = encode_txt(open_dev);
        Advert b2;
        CHECK(t2 == raw({"v=1", "auth=0"}) && parses(t2, &b2) && !b2.paired && b2.key_id.empty());
        Advert bad;
        bad.key_id = "XYZ";
        CHECK(encode_txt(bad).empty());   // never announce a malformed id
        bad.key_id = "0123456789ABCDEF";
        CHECK(encode_txt(bad).empty());   // lower case only: one spelling per id
        CHECK(raw({"v=1", "auth=1", "kid=0123456789abcdef"}).size() <= 255);
    }
    {   // strictness: everything the network could hand us
        CHECK(!parses(raw({"auth=1", "kid=0123456789abcdef"})));                          // no version
        CHECK(!parses(raw({"v=2", "auth=1", "kid=0123456789abcdef"})));                   // a version we do not speak
        CHECK(!parses(raw({"v=1", "kid=0123456789abcdef"})));                             // does not say whether it is paired
        CHECK(!parses(raw({"v=1", "auth=yes", "kid=0123456789abcdef"})));
        CHECK(!parses(raw({"v=1", "auth=1"})));                                           // paired but no key id
        CHECK(!parses(raw({"v=1", "auth=1", "kid=0123"})));                               // short id
        CHECK(!parses(raw({"v=1", "auth=1", "kid=0123456789abcdeg"})));                   // not hex
        CHECK(!parses(raw({"v=1", "auth=1", "kid=0123456789abcdef", "kid=fedcba9876543210"})));   // a repeated key is ambiguous
        CHECK(!parses(raw({"v=1", "auth=0", "auth=1"})));
        CHECK(!parses(raw({"v=1", "auth=0", "novalue"})));                                // no '='
        CHECK(!parses(raw({"v=1", "auth=0", "=x"})));                                     // empty key
        std::vector<uint8_t> trunc = raw({"v=1", "auth=0"});
        trunc.push_back(9);
        trunc.push_back('a');
        CHECK(!parses(trunc));                                                            // a string that runs off the end
        std::vector<uint8_t> zero = raw({"v=1", "auth=0"});
        zero.push_back(0);
        CHECK(!parses(zero));                                                             // an empty string
        Advert a;
        CHECK(parses(raw({"v=1", "auth=0", "future=thing"}), &a) && !a.paired);           // unknown keys are ignored
        CHECK(parses(raw({"V=1", "AUTH=1", "KID=0123456789abcdef"}), &a) && a.paired);    // keys are case-insensitive, values are not
        CHECK(!parses(raw({"v=1", "auth=1", "kid=0123456789ABCDEF"})));
        CHECK(parse_txt(nullptr, 0, &a) == false);
        // a string that claims more bytes than the record has, where the missing bytes happen to exist in memory: still refused
        std::vector<uint8_t> whole = raw({"v=1", "auth=0"});
        CHECK(parse_txt(whole.data(), whole.size(), &a));
        CHECK(!parse_txt(whole.data(), whole.size() - 2, &a));                            // "auth=0" cut to "auth": its length byte says 6
        CHECK(!parse_txt(whole.data(), whole.size() - 1, &a));
    }
    // ---- specs
    {
        std::string err;
        auto m = parse_mdns_spec(std::string("mdns:kitchen-pi@") + KID, &err);
        CHECK(m && m->name == "kitchen-pi" && m->key_id == KID);
        auto m2 = parse_mdns_spec(std::string("mdns:@") + KID, &err);
        CHECK(m2 && m2->name.empty() && m2->key_id == KID);
        auto m3 = parse_mdns_spec(std::string("mdns:my pi@2@") + KID, &err);
        CHECK(m3 && m3->name == "my pi@2");   // the key id is whatever follows the LAST '@'
        CHECK(!parse_mdns_spec("mdns:kitchen-pi", &err) && err.find("key id") != std::string::npos);   // no key id: refused, and told why
        CHECK(!parse_mdns_spec("mdns:0123456789abcdef", &err));   // a bare key id is not a spec: it has to be NAME@KEYID (or @KEYID)
        CHECK(!parse_mdns_spec("mdns:", &err) && !parse_mdns_spec("mdns:@", &err));
        CHECK(!parse_mdns_spec("mdns:kitchen-pi@", &err));
        CHECK(!parse_mdns_spec("mdns:kitchen-pi@0123", &err));
        CHECK(!parse_mdns_spec(std::string("mdns:kitchen-pi@") + "0123456789ABCDEF", &err));
        CHECK(!parse_mdns_spec(std::string("mdns:") + std::string(64, 'n') + "@" + KID, &err));   // an instance name is at most 63 bytes
        CHECK(!parse_mdns_spec(std::string("host:9100@") + KID, &err));
        CHECK(is_mdns_spec("mdns:x@y") && !is_mdns_spec("host:9100") && !is_mdns_spec("mdns") && !is_mdns_spec(""));
        CHECK(valid_key_id(KID) && !valid_key_id("") && !valid_key_id(std::string(17, 'a')) && !valid_key_id(std::string(15, 'a')));
        CHECK(valid_instance_name("a") && valid_instance_name(std::string(63, 'a')) && !valid_instance_name("") && !valid_instance_name(std::string(64, 'a')) &&
              !valid_instance_name("a\nb") && !valid_instance_name(std::string("a\x7f")));
    }
    // ---- choosing
    {
        std::vector<Found> all = {dev("zeta", "zeta.local", 9100, KID, true), dev("alpha", "alpha.local", 9101, KID, true), dev("other", "o.local", 1, KID2, true)};
        auto p = pick(all, KID);
        CHECK(p && p->name == "alpha" && p->port == 9101);                  // deterministic: the smallest name
        CHECK(pick(all, KID2) && pick(all, KID2)->host == "o.local");
        CHECK(!pick(all, "0000000000000000"));
        CHECK(pick({dev("alpha", "alpha.local", 9101, KID, true), dev("zeta", "zeta.local", 9100, KID, true)}, KID)->name == "alpha");   // whatever the order
        CHECK(!pick({}, KID));
        CHECK(!pick({dev("x", "x.local", 9100, KID, false)}, KID));         // an unpaired device is never followed, even with a matching id
        CHECK(!pick({dev("x", "", 9100, KID, true)}, KID));                 // no host
        CHECK(!pick({dev("x", "x.local", 0, KID, true)}, KID));             // no port
        CHECK(pick({dev("x", "x.local", 9100, KID, false), dev("y", "y.local", 9100, KID, true)}, KID)->name == "y");
        CHECK(instance_name_from_host("Kitchen-Pi.local") == "Kitchen-Pi" && instance_name_from_host("plain") == "plain" && instance_name_from_host("a.b.c") == "a");
        CHECK(instance_name_from_host("") == "tierfs-device" && instance_name_from_host(".local") == "tierfs-device");
        CHECK(instance_name_from_host(std::string(100, 'x')) == std::string(63, 'x') && instance_name_from_host(std::string(100, 'x') + ".local").size() == 63);
        CHECK(instance_name_from_host("a\nb\x7f" "c") == "abc");
        {
            char hn[256] = {0};
            gethostname(hn, sizeof hn - 1);
            CHECK(default_instance_name() == instance_name_from_host(hn));   // it is this machine's name
        }
        CHECK(!default_instance_name().empty() && default_instance_name().size() <= 63 && default_instance_name().find('.') == std::string::npos);
    }
    // ---- the real thing: publish through the system's mDNS service, find it again
    {
        char unique[64];
        snprintf(unique, sizeof unique, "tierfs-test-%d", static_cast<int>(getpid()));
        std::string err;
        Advert a;
        a.key_id = KID;
        a.paired = true;
        auto adv = Advertiser::start(unique, 39123, a, &err);
        CHECK(adv != nullptr);
        if (!adv) printf("  advertiser: %s\n", err.c_str());
        if (adv) {
            CHECK(adv->name() == unique);
            std::string berr;
            auto found = browse(8000, &berr, [&](const Found& f) { return f.name == unique; });
            if (!berr.empty()) printf("  browse: %s\n", berr.c_str());
            bool seen = false;
            for (const auto& f : found)
                if (f.name == unique) {
                    seen = true;
                    CHECK(f.port == 39123 && f.key_id == KID && f.paired && !f.host.empty() && f.host.back() != '.');
                }
            CHECK(seen);
            CHECK(pick(found, KID) && pick(found, KID)->name.size() > 0);
            // a name already taken is renamed by the system, not an error
            auto adv2 = Advertiser::start(unique, 39124, a, &err);
            CHECK(adv2 != nullptr);
            adv2.reset();
            adv.reset();   // withdrawn: it disappears
            std::this_thread::sleep_for(std::chrono::milliseconds(500));
            auto gone = browse(1500, &berr, nullptr);
            bool still = false;
            for (const auto& f : gone) if (f.name == unique && f.port == 39123) still = true;
            CHECK(!still);
        }
        CHECK(!Advertiser::start("", 39123, a, &err) && !err.empty());
        CHECK(!Advertiser::start(unique, 0, a, &err));
        Advert bad;
        bad.key_id = "nothex";
        CHECK(!Advertiser::start(unique, 39123, bad, &err));
    }
    printf(failures ? "\n%d FAILED\n" : "\nALL PASSED\n", failures);
    return failures ? 1 : 0;
}
