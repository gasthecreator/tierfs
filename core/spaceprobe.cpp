#include "spaceprobe.hpp"

#include <sys/statvfs.h>

#include <cstdio>
#include <cstring>

#ifdef __APPLE__
#include <CoreFoundation/CoreFoundation.h>
#endif

namespace tierfs {
namespace {

class SystemProbe : public SpaceProbe {
public:
    explicit SystemProbe(std::string path) : path_(std::move(path)) {}

    SpaceInfo measure() override {
        SpaceInfo s;
        struct statvfs sv;
        if (statvfs(path_.c_str(), &sv) == 0) {
            s.total = static_cast<uint64_t>(sv.f_blocks) * sv.f_frsize;
            s.avail_raw = static_cast<uint64_t>(sv.f_bavail) * sv.f_frsize;
        }
#ifdef __APPLE__
        CFURLRef url = CFURLCreateFromFileSystemRepresentation(nullptr, reinterpret_cast<const UInt8*>(path_.data()),
                                                               static_cast<CFIndex>(path_.size()), true);
        if (url) {
            CFTypeRef v = nullptr;
            CFErrorRef err = nullptr;
            if (CFURLCopyResourcePropertyForKey(url, kCFURLVolumeAvailableCapacityForImportantUsageKey, &v, &err) && v) {
                long long n = 0;
                if (CFGetTypeID(v) == CFNumberGetTypeID() && CFNumberGetValue(static_cast<CFNumberRef>(v), kCFNumberLongLongType, &n) && n > 0)
                    s.avail_important = static_cast<uint64_t>(n);
                CFRelease(v);
            }
            if (err) CFRelease(err);
            CFRelease(url);
        }
#endif
        return s;
    }

    int local_snapshots() override {
        FILE* f = popen(("tmutil listlocalsnapshots '" + path_ + "' 2>/dev/null").c_str(), "r");
        if (!f) return 0;
        char line[512];
        int n = 0;
        while (fgets(line, sizeof line, f)) if (strstr(line, "com.apple")) n++;
        pclose(f);
        return n;
    }

private:
    std::string path_;
};

}  // namespace

std::unique_ptr<SpaceProbe> make_system_probe(const std::string& path) { return std::make_unique<SystemProbe>(path); }

}  // namespace tierfs
