#pragma once

#include <QByteArray>
#include <QString>

#include <cstddef>
#include <functional>
#include <optional>
#include <utility>

namespace interceptor {

class M6HelperSessionIdentityTests;

class HelperSessionIdentity final {
  public:
    static constexpr std::size_t sessionRandomBytes = 16;
    static constexpr std::size_t capabilityRandomBytes = 32;

    HelperSessionIdentity(const HelperSessionIdentity &) = delete;
    HelperSessionIdentity &operator=(const HelperSessionIdentity &) = delete;
    HelperSessionIdentity(HelperSessionIdentity &&other) noexcept;
    HelperSessionIdentity &operator=(HelperSessionIdentity &&) = delete;
    ~HelperSessionIdentity();

    static std::optional<HelperSessionIdentity> create();

    const QString &sessionId() const { return sessionId_; }
    QByteArray takeCapability() &&;

  private:
    using EntropySource = std::function<bool(unsigned char *, std::size_t)>;

    HelperSessionIdentity(QString sessionId, QByteArray capability)
        : sessionId_(std::move(sessionId)), capability_(std::move(capability)) {}
    static std::optional<HelperSessionIdentity> createWithEntropy(const EntropySource &entropy);
    void wipeCapability() noexcept;

    QString sessionId_;
    QByteArray capability_;

    friend class M6HelperSessionIdentityTests;
};

} // namespace interceptor
