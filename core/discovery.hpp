// Finding devices on the local network with Bonjour (mDNS / DNS-SD), and announcing one (docs/adr/0013).
//
// Discovery is a LOCATOR and nothing else. An advertisement says "a tierfs device with key id K is at host:port"; anybody on the network can
// publish any advertisement, so nothing is ever trusted because of one. The Mac still has to prove it holds the pairing secret for K and the
// device has to prove the same (protocol v4, the secure channel), and the ledger still checks which device it is (its device id). A forged
// advertisement can therefore only fail to connect; it cannot read data or receive any. For the same reason the daemon refuses to follow an
// advertisement for a device it has no pairing secret for, and a device that is not paired refuses to advertise itself.
//
// The wire form of an advertisement (the TXT record) and the choice among found devices are plain functions with no network in them, so the
// rules can be tested exactly; only `browse` and `Advertiser` touch the system's mDNS service (dns_sd.h; built into macOS, avahi provides it on Linux).
#pragma once

#include <cstdint>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace tierfs::discovery {

constexpr const char* SERVICE_TYPE = "_tierfs._tcp";
constexpr int TXT_VERSION = 1;

// One device found on the network.
struct Found {
    std::string name;     // the instance name, a human label ("kitchen-pi")
    std::string host;     // the host name to connect to ("kitchen-pi.local"), no trailing dot
    uint16_t port = 0;
    std::string key_id;   // lower-case hex of the pairing key id (16 characters); empty when the device did not say
    bool paired = false;  // the device says it requires the authenticated channel
    bool operator==(const Found& o) const { return name == o.name && host == o.host && port == o.port && key_id == o.key_id && paired == o.paired; }
};

// What a device announces about itself.
struct Advert {
    std::string key_id;
    bool paired = false;
};

// The TXT record: length-prefixed "key=value" strings (RFC 6763 section 6): "v=1", "auth=1|0", "kid=<hex>". Empty when the advert cannot be encoded.
std::vector<uint8_t> encode_txt(const Advert& a);
// Reads a TXT record from the network. Strict: it refuses a record of another version, a bad key id, a repeated key, a malformed string, or one
// that does not say whether the device is paired. Unknown keys are ignored (room to grow).
bool parse_txt(const uint8_t* data, size_t len, Advert* out);

// "mdns:NAME@KEYID" or "mdns:@KEYID": the device list entry that follows a device around the network. NAME is only a label for people; the key id
// decides. The key id is required: the daemon will not follow an advertisement for a device it holds no secret for.
struct MdnsSpec {
    std::string name, key_id;
};
bool is_mdns_spec(const std::string& spec);
std::optional<MdnsSpec> parse_mdns_spec(const std::string& spec, std::string* err);
bool valid_key_id(const std::string& s);   // exactly 16 lower-case hex characters

// Which of the found devices a spec means: one that announces exactly this key id AND says it is paired. When several do (the same device on two
// networks, or a stale record), the one with the smallest instance name is taken so the choice does not change from run to run.
std::optional<Found> pick(const std::vector<Found>& found, const std::string& key_id);

// A valid DNS-SD instance name for this machine: the host name without its domain, cut to 63 bytes; "tierfs-device" if there is none.
std::string default_instance_name();
// The same rule for a given host name ("Kitchen-Pi.local" -> "Kitchen-Pi"): the part before the first dot, without control characters, at most 63 bytes.
std::string instance_name_from_host(const std::string& host);
// An instance name is 1 to 63 bytes with no control characters.
bool valid_instance_name(const std::string& s);

// Looks for devices for `timeout_ms`. Returns early as soon as `want` (when given) accepts a resolved device. `*err` is set when the system's mDNS
// service cannot be used (not "nothing found": that is an empty list).
std::vector<Found> browse(int timeout_ms, std::string* err, const std::function<bool(const Found&)>& want = nullptr);

// Announces a device while this object lives. Registration is confirmed by the system before `start` returns, so a failure is reported, not lost.
class Advertiser {
public:
    static std::unique_ptr<Advertiser> start(const std::string& name, uint16_t port, const Advert& advert, std::string* err);
    ~Advertiser();
    Advertiser(const Advertiser&) = delete;
    Advertiser& operator=(const Advertiser&) = delete;
    // The name actually registered (the system adds " (2)" when the name is taken).
    const std::string& name() const { return name_; }
    struct Impl;   // the system registration (internal)

private:
    Advertiser() = default;
    std::unique_ptr<Impl> impl_;
    std::string name_;
};

}  // namespace tierfs::discovery
