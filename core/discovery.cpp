#include "discovery.hpp"

#include <unistd.h>

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <chrono>
#include <cstring>
#include <map>
#include <mutex>
#include <thread>

#include <arpa/inet.h>
#include <sys/select.h>

#if __has_include(<dns_sd.h>)
#include <dns_sd.h>
#include <cstdint>
#include <cstdlib>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#define TIERFS_HAVE_DNSSD 1
#endif

namespace tierfs::discovery {

bool valid_key_id(const std::string& s) {
    if (s.size() != 16) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'))) return false;
    return true;
}

bool valid_instance_name(const std::string& s) {
    if (s.empty() || s.size() > 63) return false;
    for (unsigned char c : s)
        if (c < 0x20 || c == 0x7f) return false;
    return true;
}

// ---------------------------------------------------------------- the TXT record

std::vector<uint8_t> encode_txt(const Advert& a) {
    std::vector<std::string> items = {"v=" + std::to_string(TXT_VERSION), std::string("auth=") + (a.paired ? "1" : "0")};
    if (!a.key_id.empty()) {
        if (!valid_key_id(a.key_id)) return {};
        items.push_back("kid=" + a.key_id);
    }
    std::vector<uint8_t> out;
    for (const auto& it : items) {
        out.push_back(static_cast<uint8_t>(it.size()));
        out.insert(out.end(), it.begin(), it.end());
    }
    return out;
}

bool parse_txt(const uint8_t* data, size_t len, Advert* out) {
    std::map<std::string, std::string> kv;
    size_t i = 0;
    while (i < len) {
        size_t n = data[i++];
        if (n == 0 || i + n > len) return false;  // an empty string or one that runs past the end: not a record we wrote
        std::string item(reinterpret_cast<const char*>(data + i), n);
        i += n;
        size_t eq = item.find('=');
        if (eq == std::string::npos || eq == 0) return false;
        std::string key = item.substr(0, eq);
        for (auto& c : key) c = static_cast<char>(tolower(static_cast<unsigned char>(c)));  // DNS-SD keys are case-insensitive
        if (!kv.emplace(key, item.substr(eq + 1)).second) return false;                     // a repeated key is ambiguous
    }
    auto v = kv.find("v");
    if (v == kv.end() || v->second != std::to_string(TXT_VERSION)) return false;
    auto auth = kv.find("auth");
    if (auth == kv.end() || (auth->second != "0" && auth->second != "1")) return false;
    Advert a;
    a.paired = auth->second == "1";
    if (auto k = kv.find("kid"); k != kv.end()) {
        if (!valid_key_id(k->second)) return false;
        a.key_id = k->second;
    }
    if (a.paired && a.key_id.empty()) return false;  // a paired device that does not say which secret it wants cannot be matched
    if (out) *out = a;
    return true;
}

// ---------------------------------------------------------------- specs

bool is_mdns_spec(const std::string& spec) { return spec.compare(0, 5, "mdns:") == 0; }

std::optional<MdnsSpec> parse_mdns_spec(const std::string& spec, std::string* err) {
    auto fail = [&](const std::string& m) -> std::optional<MdnsSpec> {
        if (err) *err = m;
        return std::nullopt;
    };
    if (!is_mdns_spec(spec)) return fail("not an mdns: device entry: " + spec);
    std::string rest = spec.substr(5);
    size_t at = rest.rfind('@');
    if (at == std::string::npos)
        return fail(
            "a discovered device needs its key id so that it can be told apart from an impostor: mdns:NAME@KEYID (tierctl discover prints it)");
    MdnsSpec m;
    m.name = rest.substr(0, at);
    m.key_id = rest.substr(at + 1);
    if (!valid_key_id(m.key_id)) return fail("the key id in " + spec + " must be 16 lower-case hex characters");
    if (!m.name.empty() && !valid_instance_name(m.name)) return fail("the device name in " + spec + " is not a valid name");
    return m;
}

std::optional<Found> pick(const std::vector<Found>& found, const std::string& key_id) {
    std::optional<Found> best;
    for (const auto& f : found) {
        if (!f.paired || f.key_id != key_id || f.host.empty() || f.port == 0) continue;
        if (!best || f.name < best->name) best = f;
    }
    return best;
}

std::string default_instance_name() {
    char buf[256] = {0};
    std::string n;
    if (gethostname(buf, sizeof buf - 1) == 0) n = buf;
    return instance_name_from_host(n);
}

std::string instance_name_from_host(const std::string& host) {
    std::string n = host;
    if (size_t dot = n.find('.'); dot != std::string::npos) n.resize(dot);
    std::string clean;
    for (unsigned char c : n)
        if (c >= 0x20 && c != 0x7f) clean += static_cast<char>(c);
    if (clean.size() > 63) clean.resize(63);
    return clean.empty() ? "tierfs-device" : clean;
}

// ---------------------------------------------------------------- the system's mDNS service

#ifdef TIERFS_HAVE_DNSSD
namespace {

int64_t now_ms() { return std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now().time_since_epoch()).count(); }

std::string describe(DNSServiceErrorType e) { return "the system's mDNS service failed (DNS-SD error " + std::to_string(e) + ")"; }

struct BrowseCtx {
    DNSServiceRef main = nullptr;
    std::vector<DNSServiceRef> resolves;
    std::vector<Found> found;
    std::string error;
    std::function<bool(const Found&)> want;
    bool satisfied = false;
};

void DNSSD_API resolve_cb(DNSServiceRef, DNSServiceFlags, uint32_t, DNSServiceErrorType err, const char* fullname, const char* hosttarget,
                          uint16_t port, uint16_t txt_len, const unsigned char* txt, void* ctx_) {
    auto* ctx = static_cast<BrowseCtx*>(ctx_);
    if (err != kDNSServiceErr_NoError || !hosttarget) return;
    Advert ad;
    if (!parse_txt(txt, txt_len, &ad)) return;  // not one of ours, or not a version we speak
    Found f;
    // fullname is "<instance>._tierfs._tcp.local.": the instance may contain escaped characters; the part before the type is what people see
    std::string full = fullname ? fullname : "";
    std::string marker = std::string(".") + SERVICE_TYPE;
    size_t cut = full.find(marker);
    f.name = cut == std::string::npos ? full : full.substr(0, cut);
    std::string unesc;
    for (size_t i = 0; i < f.name.size(); i++) {  // undo DNS escaping: "\032" (decimal) and "\." style
        if (f.name[i] == '\\' && i + 1 < f.name.size()) {
            if (i + 3 < f.name.size() && isdigit(static_cast<unsigned char>(f.name[i + 1])) && isdigit(static_cast<unsigned char>(f.name[i + 2])) &&
                isdigit(static_cast<unsigned char>(f.name[i + 3]))) {
                unesc += static_cast<char>(atoi(f.name.substr(i + 1, 3).c_str()));
                i += 3;
            } else {
                unesc += f.name[++i];
            }
        } else {
            unesc += f.name[i];
        }
    }
    f.name = unesc;
    f.host = hosttarget;
    while (!f.host.empty() && f.host.back() == '.') f.host.pop_back();
    f.port = ntohs(port);
    f.key_id = ad.key_id;
    f.paired = ad.paired;
    if (f.host.empty() || f.port == 0) return;
    for (const auto& have : ctx->found)
        if (have == f) return;  // the same device seen on another interface
    ctx->found.push_back(f);
    if (ctx->want && ctx->want(f)) ctx->satisfied = true;
}

void DNSSD_API browse_cb(DNSServiceRef, DNSServiceFlags flags, uint32_t ifindex, DNSServiceErrorType err, const char* name, const char* type,
                         const char* domain, void* ctx_) {
    auto* ctx = static_cast<BrowseCtx*>(ctx_);
    if (err != kDNSServiceErr_NoError) {
        ctx->error = describe(err);
        return;
    }
    if (!(flags & kDNSServiceFlagsAdd)) return;
    DNSServiceRef r = ctx->main;
    DNSServiceErrorType e = DNSServiceResolve(&r, kDNSServiceFlagsShareConnection, ifindex, name, type, domain, resolve_cb, ctx);
    if (e == kDNSServiceErr_NoError) ctx->resolves.push_back(r);
}

}  // namespace

std::vector<Found> browse(int timeout_ms, std::string* err, const std::function<bool(const Found&)>& want) {
    BrowseCtx ctx;
    ctx.want = want;
    DNSServiceErrorType e = DNSServiceCreateConnection(&ctx.main);
    if (e != kDNSServiceErr_NoError) {
        if (err) *err = describe(e);
        return {};
    }
    DNSServiceRef br = ctx.main;
    e = DNSServiceBrowse(&br, kDNSServiceFlagsShareConnection, kDNSServiceInterfaceIndexAny, SERVICE_TYPE, nullptr, browse_cb, &ctx);
    if (e != kDNSServiceErr_NoError) {
        if (err) *err = describe(e);
        DNSServiceRefDeallocate(ctx.main);
        return {};
    }
    const int fd = DNSServiceRefSockFD(ctx.main);
    const int64_t deadline = now_ms() + std::max(0, timeout_ms);
    while (!ctx.satisfied && ctx.error.empty()) {
        int64_t left = deadline - now_ms();
        if (left <= 0) break;
        fd_set rs;
        FD_ZERO(&rs);
        FD_SET(fd, &rs);
        timeval tv;
        tv.tv_sec = static_cast<long>(left / 1000);
        tv.tv_usec = static_cast<int>((left % 1000) * 1000);
        int n = select(fd + 1, &rs, nullptr, nullptr, &tv);
        if (n < 0 && errno == EINTR) continue;
        if (n < 0) {
            ctx.error = "waiting for the system's mDNS service failed";
            break;
        }
        if (n > 0 && DNSServiceProcessResult(ctx.main) != kDNSServiceErr_NoError) {
            ctx.error = "the system's mDNS service stopped answering";
            break;
        }
    }
    for (auto r : ctx.resolves) DNSServiceRefDeallocate(r);  // sub-references first, then the connection
    DNSServiceRefDeallocate(br);
    DNSServiceRefDeallocate(ctx.main);
    if (!ctx.error.empty() && err) *err = ctx.error;
    return ctx.found;
}

struct Advertiser::Impl {
    DNSServiceRef ref = nullptr;
    std::thread pump;
    std::atomic<bool> stop{false};
    std::atomic<int> state{0};  // 0 waiting, 1 registered, -1 failed
    std::mutex mu;
    std::string name, error;
};

namespace {
void DNSSD_API register_cb(DNSServiceRef, DNSServiceFlags, DNSServiceErrorType err, const char* name, const char*, const char*, void* ctx) {
    auto* im = static_cast<Advertiser::Impl*>(ctx);
    std::lock_guard<std::mutex> g(im->mu);
    if (err == kDNSServiceErr_NoError) {
        im->name = name ? name : "";
        im->state = 1;
    } else {
        im->error = describe(err);
        im->state = -1;
    }
}
}  // namespace

std::unique_ptr<Advertiser> Advertiser::start(const std::string& name, uint16_t port, const Advert& advert, std::string* err) {
    auto fail = [&](const std::string& m) -> std::unique_ptr<Advertiser> {
        if (err) *err = m;
        return nullptr;
    };
    if (!valid_instance_name(name)) return fail("the device name must be 1 to 63 characters without control characters");
    if (port == 0) return fail("cannot advertise port 0");
    std::vector<uint8_t> txt = encode_txt(advert);
    if (txt.empty()) return fail("the advertisement could not be encoded (bad key id)");
    std::unique_ptr<Advertiser> a(new Advertiser());
    a->impl_ = std::make_unique<Impl>();
    Impl* im = a->impl_.get();
    DNSServiceErrorType e = DNSServiceRegister(&im->ref, 0, kDNSServiceInterfaceIndexAny, name.c_str(), SERVICE_TYPE, nullptr, nullptr, htons(port),
                                               static_cast<uint16_t>(txt.size()), txt.data(), register_cb, im);
    if (e != kDNSServiceErr_NoError) return fail(describe(e));
    const int fd = DNSServiceRefSockFD(im->ref);
    im->pump = std::thread([im, fd] {
        while (!im->stop) {
            fd_set rs;
            FD_ZERO(&rs);
            FD_SET(fd, &rs);
            timeval tv{0, 100000};
            int n = select(fd + 1, &rs, nullptr, nullptr, &tv);
            if (n > 0 && DNSServiceProcessResult(im->ref) != kDNSServiceErr_NoError) {
                std::lock_guard<std::mutex> g(im->mu);
                if (im->state == 0) {
                    im->error = "the system's mDNS service stopped answering";
                    im->state = -1;
                }
                return;
            }
        }
    });
    const int64_t deadline = now_ms() + 5000;
    while (im->state == 0 && now_ms() < deadline) usleep(20000);
    if (im->state != 1) {
        std::string why = im->state == -1 ? im->error : "the system's mDNS service did not confirm the registration";
        return fail(why);  // ~Advertiser stops the thread and releases the registration
    }
    a->name_ = im->name;
    return a;
}

Advertiser::~Advertiser() {
    if (!impl_) return;
    impl_->stop = true;
    if (impl_->pump.joinable()) impl_->pump.join();
    if (impl_->ref) DNSServiceRefDeallocate(impl_->ref);
}

#else  // no DNS-SD on this system

std::vector<Found> browse(int, std::string* err, const std::function<bool(const Found&)>&) {
    if (err) *err = "this build has no DNS-SD (Bonjour) support";
    return {};
}
struct Advertiser::Impl {};
std::unique_ptr<Advertiser> Advertiser::start(const std::string&, uint16_t, const Advert&, std::string* err) {
    if (err) *err = "this build has no DNS-SD (Bonjour) support";
    return nullptr;
}
Advertiser::~Advertiser() = default;

#endif

}  // namespace tierfs::discovery
