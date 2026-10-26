#define __STDC_WANT_LIB_EXT1__ 1
#include "HelperSessionIdentity.hpp"

#include <Security/SecRandom.h>
#include <string.h>

#include <array>
#include <utility>

namespace interceptor {
namespace {

bool systemEntropy(unsigned char *destination, std::size_t length) {
    if (destination == nullptr || length == 0)
        return false;
    return SecRandomCopyBytes(kSecRandomDefault, length, destination) == errSecSuccess;
}

void wipeBytes(void *data, std::size_t length) noexcept {
    if (data != nullptr && length != 0)
        (void)memset_s(data, length, 0, length);
}

class WipeGuard final {
  public:
    WipeGuard(void *data, std::size_t length) : data_(data), length_(length) {}
    WipeGuard(const WipeGuard &) = delete;
    WipeGuard &operator=(const WipeGuard &) = delete;
    ~WipeGuard() { wipeBytes(data_, length_); }

  private:
    void *data_;
    std::size_t length_;
};

} // namespace

HelperSessionIdentity::HelperSessionIdentity(HelperSessionIdentity &&other) noexcept
    : sessionId_(std::move(other.sessionId_)), capability_(std::move(other.capability_)) {}

HelperSessionIdentity::~HelperSessionIdentity() { wipeCapability(); }

QByteArray HelperSessionIdentity::takeCapability() && {
    QByteArray capability = std::move(capability_);
    capability_.clear();
    return capability;
}

void HelperSessionIdentity::wipeCapability() noexcept {
    if (!capability_.isEmpty())
        wipeBytes(capability_.data(), static_cast<std::size_t>(capability_.size()));
    capability_.clear();
}

std::optional<HelperSessionIdentity> HelperSessionIdentity::create() {
    return createWithEntropy(systemEntropy);
}

std::optional<HelperSessionIdentity>
HelperSessionIdentity::createWithEntropy(const EntropySource &entropy) {
    if (!entropy)
        return std::nullopt;

    std::array<unsigned char, sessionRandomBytes> sessionBytes{};
    std::array<unsigned char, capabilityRandomBytes> capabilityBytes{};
    const WipeGuard wipeSession{sessionBytes.data(), sessionBytes.size()};
    const WipeGuard wipeCapability{capabilityBytes.data(), capabilityBytes.size()};
    try {
        if (!entropy(sessionBytes.data(), sessionBytes.size()) ||
            !entropy(capabilityBytes.data(), capabilityBytes.size())) {
            return std::nullopt;
        }
    } catch (...) {
        return std::nullopt;
    }

    const QByteArray rawSession(reinterpret_cast<const char *>(sessionBytes.data()),
                                static_cast<qsizetype>(sessionBytes.size()));
    const QString sessionId = QString::fromLatin1(rawSession.toHex());
    QByteArray capability(reinterpret_cast<const char *>(capabilityBytes.data()),
                          static_cast<qsizetype>(capabilityBytes.size()));
    if (sessionId.size() != static_cast<qsizetype>(sessionRandomBytes * 2) ||
        capability.size() != static_cast<qsizetype>(capabilityRandomBytes)) {
        wipeBytes(capability.data(), static_cast<std::size_t>(capability.size()));
        return std::nullopt;
    }
    return HelperSessionIdentity(sessionId, std::move(capability));
}

} // namespace interceptor
